const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
let options;
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'web/app.js'),'utf8'), {
  Vue:{createApp(value){options=value;return {mount(){}};}},
  setTimeout,clearTimeout,setInterval,clearInterval,URLSearchParams,console
});
function model(extra={}) {
  const data=Object.assign(options.data(),extra);
  for(const [key,fn] of Object.entries(options.methods))data[key]=fn.bind(data);
  for(const [key,fn] of Object.entries(options.computed))Object.defineProperty(data,key,{get:fn.bind(data)});
  return data;
}
const result=(m,j)=>m.runOutcome?m.runOutcome(j).label:m.statusLabel(j.status);
test('an ended job with a failed source is partial rather than successful',()=>{
  const m=model();const job={status:'done',stats:{new:1},source_stats:[{source:'certspotter',complete:true},{source:'subfinder',error:'denied',error_code:'scope_denied'}]};
  assert.equal(result(m,job),'部分成功');
});
test('all sources failing without retained results is a failed result',()=>{
  assert.equal(result(model(),{status:'done',stats:{new:0,updated:0},source_stats:[{source:'hunter',error:'unavailable'}]}),'失败');
});
test('absence eligibility and evidence-only mode do not mean collection failed',()=>{
  assert.equal(result(model(),{status:'done',stats:{collection_mode:'evidence_only',complete:false,warning:'legacy coverage warning'},source_stats:[{source:'certspotter',complete:true,absence_usable:false}]}),'成功');
});
test('old ended jobs without result evidence are explicitly unknown',()=>{
  assert.equal(result(model(),{status:'done',stats:{},source_stats:[]}),'已完成，结果待核对');
});
test('cancelled and running jobs keep their actual execution status',()=>{
  const m=model();assert.equal(result(m,{status:'cancelled'}),'已取消');assert.equal(result(m,{status:'running'}),'运行中');
});
test('HTTP permission is described separately from actual observations',()=>{
  const m=model();assert.equal(typeof m.scopeHTTPPolicy,'function');
  assert.match(m.scopeHTTPPolicy({active:true,confirmed:true,project_policy:{enabled:true,allow_active:true}},'evidence_only'),/不发送.*HTTP/);
  assert.match(m.scopeHTTPPolicy({active:false,confirmed:true},'profile'),/未启用/);
  assert.match(m.scopeHTTPPolicy({active:true,confirmed:true,project_policy:{enabled:true,allow_active:false}},'profile'),/项目.*不允许/);
  assert.match(m.scopeHTTPPolicy({active:true,confirmed:true,project_policy:{enabled:true,allow_active:true}},'profile'),/允许/);
  assert.match(m.assetHTTPState({status_code:0,is_alive:null}),/尚无.*HTTP/);
  assert.match(m.assetHTTPState({status_code:200,is_alive:true}),/HTTP.*不保证.*在线/);
  assert.doesNotMatch(m.assetHTTPState({status_code:0,is_alive:false}),/HTTP.*(?:失败|未成功)/);
});
test('exact targets cannot enqueue subfinder and changing scope never expands authorization',async()=>{
  const scope={id:1,domain:'example.com',mode:'exact',active:false};
  const m=model({selectedScope:1,state:{scopes:[scope],source_options:['certspotter','subfinder']},plan:{collectors:['subfinder'],collection_mode:'profile'}});
  const requests=[];m.request=async(...args)=>{requests.push(args);return {job:1};};m.loadState=async()=>{};
  await m.collect();assert.equal(requests.length,0);assert.match(m.message,/精确域名|不支持/);assert.equal(scope.mode,'exact');
});
test('source compatibility also respects evidence-only and custom manifest modes',()=>{
  const m=model({state:{source_options:['certspotter','subfinder','fixture'],source_capabilities:[{name:'fixture',enabled:true,scope_modes:['descendants'],evidence_only:false}]}});
  assert.equal(typeof m.sourceBlockReason,'function');
  assert.match(m.sourceBlockReason('subfinder',{mode:'exact'},'profile'),/精确域名/);
  assert.match(m.sourceBlockReason('subfinder',{mode:'descendants'},'evidence_only'),/证据/);
  assert.match(m.sourceBlockReason('fixture',{mode:'exact'},'profile'),/不支持/);
  assert.equal(m.sourceBlockReason('certspotter',{mode:'exact'},'evidence_only'),'');
});
test('events use readable summaries and do not invent HTTP evidence for old records',()=>{
  const m=model();const summary=e=>m.eventSummary?m.eventSummary(e):JSON.stringify(e.detail);
  assert.match(summary({type:'NEW_ASSET',host:'api.example.com',detail:{sources:['certspotter']}}),/新增资产.*api\.example\.com.*certspotter/);
  assert.match(summary({type:'ASSET_DOWN',host:'api.example.com',detail:{}}),/历史.*未记录.*HTTP/);
  assert.match(summary({type:'ASSET_DOWN',host:'api.example.com',detail:{evidence:'连续 3 次 HTTP 探测未成功，不等于已确认服务关闭'}}),/连续.*HTTP.*不代表/);
  assert.match(summary({type:'IP_CHANGED',host:'api.example.com',detail:{before:['1.1.1.1'],after:['8.8.8.8']}}),/1\.1\.1\.1.*8\.8\.8\.8/);
});
test('same target issue streaks ignore other targets and keep changed runs visible',()=>{
  const issue=id=>({id,scope_id:1,status:'done',stats:{new:0,updated:1},source_stats:[{source:'fixture',error:'same error',error_code:'source_http'}]});
  const newest=issue(10),other={...issue(9),scope_id:2},older=issue(8),oldest=issue(7);
  const m=model({state:{jobs:[newest,other,older,oldest]}});
  assert.equal(m.runIssueStreak(newest),3);assert.equal(m.runIssueStreak(older),0);
  assert.equal(m.runExpanded(newest),true);assert.equal(m.runExpanded(older),false);
  older.stats.new=1;assert.equal(m.runExpanded(older),true);
});
test('an old incompatible plan can still be disabled without widening its scope',async()=>{
  const scope={id:1,mode:'exact',plan:{collectors:['subfinder']}};
  const m=model({selectedScope:1,state:{scopes:[scope]},plan:{enabled:false,collectors:[],collection_mode:'profile'}});
  const requests=[];m.request=async(...args)=>{requests.push(args);return {}};m.loadState=async()=>{};
  await m.disablePlan();assert.equal(requests.length,1);
  assert.equal(requests[0][1].enabled,false);assert.equal(requests[0][1].collectors.join(','),'subfinder');assert.equal(scope.mode,'exact');
});
test('source cleanup preserves compatible choices and reports unsaved plan changes',()=>{
  const scope={id:1,mode:'exact'};
  const m=model({selectedScope:1,state:{scopes:[scope]},plan:{collectors:['certspotter','subfinder'],collection_mode:'profile'}});
  m.reconcileSourceSelections();assert.equal(m.plan.collectors.join(','),'certspotter');assert.equal(m.sourceWarnings.length,1);assert.equal(scope.mode,'exact');
});

test('primary navigation has five entries and old pages remain grouped',()=>{
  const m=model({me:{id:1,role:'admin'}});assert.equal(m.navigation.length,5);
  m.page='events';assert.equal(m.primaryPage,'assets');m.page='plugins';assert.equal(m.primaryPage,'settings');
  assert.equal(m.settingsNavigation.some(n=>n[0]==='plugins'),true);
  m.me.role='readonly';assert.equal(m.settingsNavigation.some(n=>n[0]==='plugins'),false);
});

test('manual runs use saved target defaults and block unsaved source changes',async()=>{
  const saved={enabled:false,collectors:['certspotter'],collection_mode:'evidence_only',interval_hours:24,cron:''};
  const scope={id:1,mode:'exact',plan:saved};const m=model({selectedScope:1,state:{scopes:[scope]},plan:{...saved,collectors:[...saved.collectors]}});
  const calls=[];m.request=async(...args)=>{calls.push(args);return {job:2};};m.loadState=async()=>{};m.loadTargetJobs=async()=>{};
  await m.collect();assert.equal(calls.length,1);assert.equal(JSON.stringify(calls[0][1]),'{"use_saved_config":true}');
  m.plan.collection_mode='profile';await m.collect();assert.equal(calls.length,1);assert.match(m.message,/先保存/);
});

test('selecting targets never aliases or rewrites saved source configuration',()=>{
  const scope={id:1,mode:'exact',plan:{collectors:['certspotter','subfinder'],collection_mode:'profile'}};
  const m=model({state:{scopes:[scope]}});m.selectScope(1);
  assert.equal(scope.plan.collectors.join(','),'certspotter,subfinder');assert.equal(m.plan.collectors.join(','),'certspotter');assert.equal(m.sourceConfigDirty,true);
});

test('editing a scope keeps limits and requires authorization confirmation again',()=>{
  const scope={id:1,mode:'exact',rps:0.2,concurrency:1,request_limit:99,window_start:1,window_end:2,confirmed:true,exclusions:['x.example.com']};
  const m=model({state:{scopes:[scope]}});m.editScope(scope);
  assert.equal(m.scopeForm.rps,0.2);assert.equal(m.scopeForm.request_limit,99);assert.equal(m.scopeForm.confirmed,false);assert.equal(scope.confirmed,true);
  m.scopeForm.exclusions.push('y.example.com');assert.equal(scope.exclusions.length,1);
});

test('presets stay within project rate limits and apply only on selection',()=>{
  const m=model({state:{projects:[{id:7,rps_limit:0.3}]},scopeForm:{project_id:7,rps:0.1}});
  m.applyScopePreset('aggressive');assert.equal(m.scopeForm.rps,0.3);assert.equal(m.scopeForm.concurrency,3);
});

test('batch target creation keeps failed domains for explicit retry',async()=>{
  const m=model({scopeForm:{domain:'example.com\nEXAMPLE.com\nexample.org',confirmed:true,mode:'exact',active:false},state:{scopes:[]}});
  const calls=[];m.request=async(path,body)=>{calls.push([path,body]);if(body.domain==='example.org')throw Error('duplicate');return {id:1};};m.loadState=async()=>{};
  await m.saveScope();assert.equal(calls.length,2);assert.equal(m.scopeForm.domain,'example.org');assert.equal(m.scopeForm.confirmed,false);assert.equal(m.isError,true);assert.match(m.message,/已保存 1/);
});

test('enterprise handoff carries project and domain without creating or probing',async()=>{
  const m=model({me:{id:1,role:'admin'}});const c={id:8,project_id:9,domain:'example.org',status:'confirmed'};
  const calls=[];m.request=async(...args)=>{calls.push(args);return {id:4};};m.loadState=async()=>{};
  await m.importEnterprise(c);assert.equal(calls.length,0);assert.equal(m.scopeForm.project_id,9);assert.equal(m.scopeForm.domain,c.domain);assert.equal(m.scopeForm.confirmed,false);
  m.scopeForm.confirmed=true;await m.saveScope();assert.equal(calls.length,1);assert.match(calls[0][0],/candidates\/8\/import-scope/);assert.equal(calls[0][1].mode,'exact');
});

test('target history requests a server-side scope filter rather than filtering a truncated global list',async()=>{
  const m=model({selectedScope:3,activeProject:'2'});let requested;m.request=async path=>{requested=path;return [{id:1,scope_id:3}];};
  await m.loadTargetJobs();assert.match(requested,/scope_id=3/);assert.match(requested,/project_id=2/);assert.equal(m.targetJobs.length,1);
});

test('saved views whitelist filter keys and partition by account and project',()=>{
  const m=model({me:{id:1},activeProject:'2'});assert.equal(m.localViewKey(),'scopedesk-views:1:2');
  const filters=m.cleanViewFilters({q:'test',page:999,project_id:8,source:'certspotter'});
  assert.equal(filters.q,'test');assert.equal(filters.page,undefined);assert.equal(filters.project_id,undefined);
  m.me.id=3;assert.equal(m.localViewKey(),'scopedesk-views:3:2');
});

test('confirming enterprise ownership immediately opens the prefilled target form',async()=>{
  const m=model({me:{id:1,role:'admin'}});const calls=[];
  m.request=async(...args)=>{calls.push(args);return {ok:true};};m.loadEnterprise=async()=>{};
  await m.reviewEnterprise({id:4,domain:'example.org',project_id:2,status:'pending'},'confirmed');
  assert.equal(calls.length,1);assert.equal(m.page,'scope');assert.equal(m.scopeForm.domain,'example.org');assert.equal(m.scopeForm.confirmed,false);
});

test('target-specific history groups repeated issues even when global recent jobs exclude them',()=>{
  const issue=id=>({id,scope_id:1,status:'done',source_stats:[{source:'certspotter',error:'temporary'}]});
  const m=model({page:'scope',targetTab:'history',targetJobs:[issue(2),issue(1)],state:{jobs:[]}});
  assert.equal(m.runIssueStreak(m.targetJobs[0]),2);assert.equal(m.runExpanded(m.targetJobs[1]),false);
});
