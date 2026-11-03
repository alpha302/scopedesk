package main

func (s *Server) hashLoginPassword(value, salt string) string {
	if s.loginHash != nil {
		return s.loginHash(value, salt)
	}
	return password(value, salt)
}
