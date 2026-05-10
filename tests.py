import unittest
import os
import json

# Configuração de ficheiros temporários para testes
TEST_DB = 'test_fista.db'
TEST_LOG = 'test_audit.log.jsonl'
TEST_BACKUP = 'test_backups'

import app as myapp

# Sobrepor configuração da aplicação para ambiente de teste
myapp.DB_FILE = TEST_DB
myapp.LOG_FILE = TEST_LOG
myapp.BACKUP_DIR = TEST_BACKUP

class FISTAUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(TEST_BACKUP):
            os.makedirs(TEST_BACKUP)

    def setUp(self):
        # Configurar aplicação para modo de teste
        myapp.app.config['TESTING'] = True
        myapp.app.config['WTF_CSRF_ENABLED'] = False
        self.client = myapp.app.test_client()
        
        # Limpar ficheiros de teste residuais
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)
        if os.path.exists(TEST_LOG):
            os.remove(TEST_LOG)
            
        # Inicializar a base de dados de teste limpa
        myapp.init_db()

    def tearDown(self):
        # Fechar ligação e remover ficheiros temporários de teste
        with myapp.app.app_context():
            if getattr(myapp.g, '_database', None):
                myapp.g._database.close()
                
        import time
        time.sleep(0.1) # Aguardar que o Windows liberte o ficheiro SQLite
        
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except PermissionError:
                pass
        if os.path.exists(TEST_LOG):
            try:
                os.remove(TEST_LOG)
            except PermissionError:
                pass

    def test_01_login_page_renders(self):
        """Teste à rota principal de login para garantir que carrega o HTML"""
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Autentica', response.data)

    def test_02_rbac_protection_dashboard(self):
        """Teste se páginas protegidas redirecionam utilizadores não autenticados"""
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 302) # Redirects to /login
        self.assertTrue(b'/login' in response.data)

    def test_03_append_only_log_creation(self):
        """Teste à funcionalidade de registo de logs de auditoria imutáveis (append-only)"""
        myapp.append_only_log("soc_tester", "ADMIN_IT", "test_action", "test_resource")
        self.assertTrue(os.path.exists(TEST_LOG))
        
        with open(TEST_LOG, 'r') as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            
            # Parse the JSON log
            log_entry = json.loads(lines[0])
            self.assertEqual(log_entry["user"], "soc_tester")
            self.assertEqual(log_entry["action"], "test_action")
            self.assertEqual(log_entry["result"], "success")

    def test_04_user_status_check(self):
        """Teste ao sistema de verificação de revogação/expiração de utilizadores"""
        from datetime import datetime, timedelta
        
        # Revoked user
        user_revoked = {"revoked": 1, "is_active": 1, "expiration_date": None}
        is_valid, msg = myapp.check_user_status(user_revoked)
        self.assertFalse(is_valid)
        self.assertEqual(msg, "Conta revogada.")
        
        # Expired user
        past_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        user_expired = {"revoked": 0, "is_active": 1, "expiration_date": past_date}
        is_valid, msg = myapp.check_user_status(user_expired)
        self.assertFalse(is_valid)
        self.assertEqual(msg, "Acesso expirado.")
        
        # Valid user
        future_date = (datetime.now() + timedelta(days=10)).strftime("%Y-%m-%d")
        user_valid = {"revoked": 0, "is_active": 1, "expiration_date": future_date}
        is_valid, msg = myapp.check_user_status(user_valid)
        self.assertTrue(is_valid)

if __name__ == '__main__':
    unittest.main()
