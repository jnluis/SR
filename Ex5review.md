### Vuln 1 - SQL Injection

Ao analisar o método **login_user** é possivel verificar que na primeira query:  
```
query = f"""
    SELECT users.username
    FROM users
    WHERE users.username = '{username}' AND users.password = '{password}'
"""

cursor.execute(query)
result = cursor.fetchone() 
```  

É possivel realizar injeção através de um comando semelhante a  
```
user = worker.login_user("admin' ;--", '')
```  
O que daria acesso à conta de admin sem introduzir a palavra-passe deste.

Para corrigir esta vulnerabilidade seria necessário utilizar *prepared statements* como no seguinte exemplo:  
```
query = f"""
    SELECT users.username
    FROM users
    WHERE users.username = ? AND users.password = ?
"""
cursor.execute(query, (username, password))
```

### Vuln 2 - Race Conditions
No método *create_user* da classe Worker, existe uma race condition.  
```
# race condition vuln
        if self.get_user_by_username(username) is None:
            self.lock.acquire()
            user = self.user_cache.create_user(username, password, roles)
            self.lock.release()
            self._db_create_user(username, user.password_hash, user.salt, roles )
            return user
```

Porque os dados são obtidos, e só depois é obtido o *lock* o que permite, que durante um breve momento exista alterações que possam alterar e danificar o fluxo do código.  
Para corrigir esta vulnerabilida o *lock* deve ser obtido mais cedo, para garantir a segurança desde o momento em que os dados são obtidos e utilizados, como demonstrado no seguinte bloco:
```
def create_user(self, username: str, password: str, roles: list = []) -> Optional[UserProfile]:
        self.lock.acquire()
        if self.get_user_by_username(username) is None:
            user = self.user_cache.create_user(username, password, roles)
            self.lock.release()
            self._db_create_user(username, user.password_hash, user.salt, roles )
            return user
        else:
            self.lock.release()
        return None
```
### Vuln 3 - Verificação da Hash
A função **verify_hash** não devolve qualquer tipo de valor, sendo a hash válida ou não, o que a torna uma função que não contribui para as verificações realizadas.  
Para corrigir esta vulnerabilidade o código seria semelhante ao seguinte:  
``` 
def verify_hash(password: str, salt: bytes, hash: str) -> bool:
    kdf = get_kdf(salt)
    try:
        kdf.verify(password.encode(), hash)
        return True
    except InvalidKey:
        return False
```

### Vuln 4 - Verificação do Role
A função **check_admin__access** apenas verifica se o valor da string role da Base de Dados contém "admin", isto pode ser um problema caso a Base de Dados seja comprometida.  
Para corrigir esta vulnerabilidade, a equipa sugere a utilização de tokens.