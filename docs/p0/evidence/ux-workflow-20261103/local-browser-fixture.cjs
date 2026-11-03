// Synthetic UI only. Never forwards requests or runs collectors/workers.
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'../../../..');
const policy={enabled:true,allow_active:true,rps_limit:1};
const plan={enabled:true,interval_hours:24,collection_mode:'profile',collectors:['certspotter','subfinder']};
const scope={id:1,owner:1,project_id:1,project_name:'界面验收',workspace_id:1,domain:'example.com',mode:'exact',confirmed:true,active:true,rps:1,concurrency:2,request_limit:1000,window_start:0,window_end:24,exclusions:[],plan,asset_count:1,project_policy:policy};
const sources=[{source:'certspotter',returned:1,in_scope:1,discarded:0,new_count:0,attempts:1,error:'',error_code:'',complete:true,rejected_fields:{}},{source:'subfinder',returned:0,in_scope:0,discarded:0,new_count:0,attempts:1,error:'插件目标被范围校验拒绝',error_code:'scope_denied',complete:false,rejected_fields:{}}];
const jobs=[9,8,7].map(id=>({id,scope_id:1,project_id:1,domain:'example.com',status:'done',created_at:'2026-11-03T08:00:00Z',trigger:'schedule',attempts:1,max_attempts:1,progress:100,source_stats:sources,stats:{new:0,updated:1,collection_mode:'profile',warning:'legacy partial message'},required_labels:[]}));
jobs.push({id:6,scope_id:1,project_id:1,domain:'example.com',status:'done',created_at:'2026-11-03T07:00:00Z',source_stats:[sources[0]],stats:{new:0,updated:1,collection_mode:'evidence_only',complete:false,warning:'legacy incomplete coverage'},required_labels:[]});
jobs.push({id:5,scope_id:1,project_id:1,domain:'example.com',status:'done',created_at:'2026-11-03T06:00:00Z',source_stats:[],stats:{},required_labels:[]});
const asset={id:1,scope_id:1,project_id:1,domain:'example.com',host:'example.com',ips:['1.1.1.1','2606:4700:4700::1111','8.8.8.8'],cnames:[],sources:['certspotter'],port:0,status_code:0,is_alive:null,title:'',fingerprints:[],status:'new',tags:[],note:'',assignee:'',category:'未分类',score:10,first_seen:'2026-11-03T08:00:00Z',last_seen:'2026-11-03T08:00:00Z',plugin_evidence:[],network_evidence:[],security_matches:[]};
const state={scopes:[scope],jobs,src:[],projects:[{id:1,owner:1,name:'界面验收',workspace_id:1,workspace_name:'本地',can_write:true,can_manage:true,...policy}],workspaces:[{id:1,name:'本地',can_manage:true}],source_options:['certspotter','subfinder'],source_capabilities:[{name:'certspotter',enabled:true,scope_modes:['exact','subdomains','descendants'],evidence_only:true},{name:'subfinder',enabled:true,scope_modes:['subdomains','descendants'],evidence_only:false}]};
const events=[{id:1,scope_id:1,host:'example.com',domain:'example.com',type:'NEW_ASSET',detail:{host:'example.com',sources:['certspotter']},created_at:'2026-11-03T08:00:00Z'},{id:2,scope_id:1,host:'example.com',domain:'example.com',type:'ASSET_DOWN',detail:{host:'example.com',miss_count:3},created_at:'2026-11-02T08:00:00Z'}];
const server=http.createServer((req,res)=>{
 const url=new URL(req.url,'http://127.0.0.1:18769');
 const send=(data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
 if(url.pathname.startsWith('/api/')){
  if(req.method!=='GET'){if(url.pathname==='/api/page')return send({ok:true});return send({error:'仅本地页面验收；不会创建任务、保存计划或发出目标请求'},409);}
  if(url.pathname==='/api/me')return send({user:{id:1,name:'fixture-admin',role:'admin'},csrf:'synthetic-only'});
  if(url.pathname==='/api/state')return send(state);
  if(url.pathname==='/api/dashboard/summary')return send({total:1,today_new:1,alive:0,active_jobs:0,trend:[]});
  if(url.pathname==='/api/assets')return send({items:[asset],total:1});
  if(url.pathname==='/api/assets/1')return send({asset,services:[],snapshots:[],events});
  if(url.pathname==='/api/jobs')return send(jobs);
  if(url.pathname==='/api/events')return send(events);
  if(url.pathname==='/api/explorations/sources')return send([{name:'manual',available:true}]);
  if(url.pathname==='/api/explorations')return send({items:[],total:0});
  if(url.pathname==='/api/explorations/candidates')return send({items:[{id:1,project_id:1,domain:'example.org',company:'示例公司',status:'confirmed',attribution_score:null,evidence:[]}],total:1});
  return send({error:'fixture endpoint unavailable'},404);
 }
 const names={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/vue.global.prod.js':'vue.global.prod.js'};
 const name=names[url.pathname];if(!name){res.writeHead(404);return res.end();}
 res.writeHead(200,{'Content-Type':name.endsWith('.js')?'application/javascript; charset=utf-8':name.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8','Cache-Control':'no-store'});
 res.end(fs.readFileSync(path.join(root,'web',name)));
});
server.listen(18769,'127.0.0.1',()=>process.stdout.write('Synthetic ScopeDesk UI fixture: http://127.0.0.1:18769; no outbound target requests\n'));
