import os
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session as flask_session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import csv
import socket
import requests
import urllib3
import logging
import ipaddress
from datetime import datetime
from ldap3 import Server, Connection, ALL, NTLM
from functools import wraps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    filename='fortigate_actions.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Gera chave secreta aleatória

# Configuração Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'

# Configurações LDAP - ALTERE CONFORME SEU AMBIENTE
LDAP_SERVER = 'ldap://tdn-dc02.tradein.net.br'
LDAP_DOMAIN = 'TRADEIN'  # Seu domínio Active Directory
LDAP_BASE_DN = 'DC=tradein,DC=net,DC=br'  # Base DN do seu domínio
LDAP_GROUP_NAME = 'Grupo_Acesso_Automacoes_Fortigate'
#LDAP_GROUP_DN = f'CN={LDAP_GROUP_NAME},OU=Grupos,DC=dominio,DC=com,DC=br'  # Ajuste conforme sua estrutura
LDAP_GROUP_DN = f'CN={LDAP_GROUP_NAME},OU=Grupos,OU=Suporte,OU=Trade in Technology,DC=tradein,DC=net,DC=br'

# Sessão global para requests
session_requests = requests.Session()
session_requests.verify = False

# Classe de usuário para Flask-Login
class User(UserMixin):
    def __init__(self, username, groups=None):
        self.id = username
        self.username = username
        self.groups = groups or []

@login_manager.user_loader
def load_user(username):
    # Recupera usuário da sessão
    if 'user_groups' in flask_session:
        return User(username, flask_session['user_groups'])
    return None

def verificar_grupo_ldap(username, password):
    """
    Autentica usuário no LDAP e verifica se pertence ao grupo autorizado
    Retorna: (autenticado, tem_acesso, grupos, mensagem_erro)
    """
    try:
        # Monta o username com domínio
        user_dn = f"{LDAP_DOMAIN}\\{username}"
        
        # Conecta ao servidor LDAP
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=NTLM,
            auto_bind=True
        )
        
        if not conn.bind():
            return False, False, [], "Credenciais inválidas"
        
        # Busca grupos do usuário
        search_filter = f'(sAMAccountName={username})'
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=['memberOf', 'displayName', 'mail']
        )
        
        if not conn.entries:
            conn.unbind()
            return False, False, [], "Usuário não encontrado no AD"
        
        user_info = conn.entries[0]
        member_of = user_info.memberOf.values if hasattr(user_info, 'memberOf') else []
        
        # Verifica se pertence ao grupo autorizado
        tem_acesso = any(LDAP_GROUP_NAME in group for group in member_of)
        
        conn.unbind()
        
        if not tem_acesso:
            logging.warning(f"Tentativa de acesso negada: {username} - não pertence ao grupo {LDAP_GROUP_NAME}")
            return True, False, member_of, f"Acesso negado. Você não pertence ao grupo '{LDAP_GROUP_NAME}'"
        
        logging.info(f"Login autorizado: {username}")
        return True, True, member_of, None
        
    except Exception as e:
        logging.error(f"Erro LDAP para {username}: {str(e)}")
        return False, False, [], f"Erro ao autenticar: {str(e)}"

# Funções do sistema (mantidas do código original)
def ler_fortigates(arquivo='fortigates.csv'):
    """Lê o arquivo CSV com os dados dos Fortigates"""
    fortigates = []
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                fortigates.append(row)
        return fortigates
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")
        return []

def validar_ip(ip):
    """Valida se o formato do IP é válido"""
    partes = ip.split('.')
    if len(partes) != 4:
        return False
    try:
        return all(0 <= int(parte) <= 255 for parte in partes)
    except ValueError:
        return False

def verificar_ip_disponivel(fortigate, timeout=3):
    """Verifica qual IP está disponível e retorna o IP e porta"""
    ips_para_testar = []
    
    if fortigate.get('ip_1') and fortigate['ip_1'].strip():
        ips_para_testar.append(('ip_1', fortigate['ip_1']))
    
    if fortigate.get('ip_2') and fortigate['ip_2'].strip():
        ips_para_testar.append(('ip_2', fortigate['ip_2']))
    
    if not ips_para_testar:
        return None
    
    for nome_ip, ip_porta in ips_para_testar:
        try:
            if ':' in ip_porta:
                ip, porta = ip_porta.rsplit(':', 1)
                porta = int(porta)
            else:
                ip = ip_porta
                porta = 443
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            resultado = sock.connect_ex((ip, porta))
            sock.close()
            
            if resultado == 0:
                return {'ip': ip, 'porta': porta, 'ip_completo': ip_porta, 'qual_ip': nome_ip}
        
        except:
            continue
    
    return None

def listar_addresses(fortigate_ip):
    """Lista todos os addresses do tipo ipmask"""
    try:
        r = session_requests.get(
            f"https://{fortigate_ip}/api/v2/cmdb/firewall/address?filter=type==ipmask",
            timeout=10
        )
        
        if r.status_code == 200:
            return r.json().get("results", [])
        else:
            logging.error(f"Erro ao listar addresses: {r.status_code}")
            return []
    except Exception as e:
        logging.error(f"Erro na requisição listar_addresses: {e}")
        return []

def verificar_allow_routing(ip_address, fortigate_ip):
    """Verifica se o address tem allow-routing habilitado"""
    try:
        r = session_requests.get(
            f"https://{fortigate_ip}/api/v2/cmdb/firewall/address/{ip_address}",
            timeout=10
        )
        
        if r.status_code == 200:
            address_data = r.json().get("results", [{}])[0]
            allow_routing = address_data.get("allow-routing", "disable")
            return allow_routing == "enable"
        else:
            return False
    except Exception as e:
        logging.error(f"Erro ao verificar allow-routing: {e}")
        return False

def atualizar_allow_routing(ip_address, fortigate_ip):
    """Atualiza o allow-routing para enable"""
    try:
        r = session_requests.put(
            f"https://{fortigate_ip}/api/v2/cmdb/firewall/address/{ip_address}",
            json={"allow-routing": "enable"},
            timeout=10
        )
        
        if r.status_code == 200:
            return {"success": True, "message": "allow-routing atualizado para enable"}
        else:
            return {"success": False, "message": f"Erro ao atualizar: {r.status_code}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def add_address(ip_address, fortigate_ip, username=None):
    """Adiciona um endereço IP no Fortigate com validações avançadas"""
    comment = f"adicionado via script por {username}" if username else "adicionado via script"

    data = {
        "name": ip_address,
        "subnet": ip_address + "/32",
        "comment": comment,
        "allow-routing": "enable"
    }

    try:
        r = session_requests.post(
            f"https://{fortigate_ip}/api/v2/cmdb/firewall/address", 
            json=data,
            timeout=10
        )
        
        if r.status_code == 200:
            return {"success": True, "message": "Address criado com sucesso"}
        elif r.status_code == 424:
            if verificar_allow_routing(ip_address, fortigate_ip):
                return {"success": True, "message": "Address já existe (allow-routing OK)"}
            else:
                result = atualizar_allow_routing(ip_address, fortigate_ip)
                if result["success"]:
                    return {"success": True, "message": "Address já existe (allow-routing corrigido)"}
                else:
                    return {"success": False, "message": f"Address existe mas falhou ao corrigir allow-routing: {result['message']}"}
        elif r.status_code == 500:
            logging.info(f"Erro 500 ao criar {ip_address}, verificando se já existe...")
            addresses = listar_addresses(fortigate_ip)
            
            address_encontrado = None
            for addr in addresses:
                if addr.get("name") == ip_address:
                    address_encontrado = addr
                    break
            
            if address_encontrado:
                if verificar_allow_routing(ip_address, fortigate_ip):
                    return {"success": True, "message": "Address já existe no sistema (allow-routing OK)"}
                else:
                    result = atualizar_allow_routing(ip_address, fortigate_ip)
                    if result["success"]:
                        return {"success": True, "message": "Address já existe (allow-routing corrigido)"}
                    else:
                        return {"success": False, "message": f"Address existe mas falhou ao corrigir: {result['message']}"}
            else:
                return {"success": False, "message": f"Erro 500 e address não encontrado no sistema"}
        else:
            return {"success": False, "message": f"Erro ao criar address: {r.status_code}"}
            
    except Exception as e:
        return {"success": False, "message": f"Erro na requisição: {str(e)}"}

def delete_address(ip_address, fortigate_ip):
    """Remove o objeto de endereço do Fortigate via DELETE"""
    try:
        r = session_requests.delete(
            f"https://{fortigate_ip}/api/v2/cmdb/firewall/address/{ip_address}",
            timeout=10
        )
        if r.status_code == 200:
            return {"success": True, "message": "Address removido do sistema"}
        else:
            return {"success": False, "message": f"Erro ao deletar: {r.status_code}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def check_group_members(group_name, fortigate_ip):
    """Verifica os membros atuais do grupo"""
    try:
        r = session_requests.get(
            f"https://{fortigate_ip}/api/v2/cmdb/firewall/addrgrp/{group_name}?datasource=1",
            timeout=10
        )
        
        if r.status_code == 200:
            return r.json()["results"][0]["member"]
        else:
            return None
            
    except Exception as e:
        return None

def add_member_to_group(group_name, fortigate_ip, members):
    """Atualiza a lista de membros do grupo"""
    data = {
        "name": group_name,
        "member": members
    }

    try:
        r = session_requests.put(
            f"https://{fortigate_ip}/api/v2/cmdb/firewall/addrgrp/{group_name}?datasource=1", 
            json=data,
            timeout=10
        )
        
        if r.status_code == 200:
            return {"success": True, "message": "Grupo atualizado"}
        else:
            return {"success": False, "message": f"Erro ao atualizar grupo: {r.status_code}"}
            
    except Exception as e:
        return {"success": False, "message": f"Erro na requisição: {str(e)}"}

def ler_excecoes(arquivo='excecoes.csv'):
    """Lê o arquivo CSV com os ranges de exceção"""
    excecoes = []
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ranges_list = [r.strip() for r in row['ranges'].split(',') if r.strip()]
                excecoes.append({
                    'cliente': row['cliente'],
                    'ranges': ranges_list
                })
        return excecoes
    except FileNotFoundError:
        logging.warning("Arquivo de exceções não encontrado")
        return []
    except Exception as e:
        logging.error(f"Erro ao ler arquivo de exceções: {e}")
        return []

def verificar_ip_em_excecoes(ip_address):
    """Verifica se o IP está em algum range de exceção"""
    excecoes = ler_excecoes()
    
    try:
        ip = ipaddress.ip_address(ip_address)
        
        for excecao in excecoes:
            cliente = excecao['cliente']
            
            for range_ip in excecao['ranges']:
                try:
                    rede = ipaddress.ip_network(range_ip, strict=False)
                    if ip in rede:
                        return True, cliente, range_ip
                except ValueError:
                    logging.error(f"Range inválido: {range_ip} do cliente {cliente}")
                    continue
        
        return False, None, None
    
    except ValueError:
        return False, None, None

def validar_ips_contra_excecoes(ips_validos):
    """Valida uma lista de IPs contra as exceções"""
    ips_permitidos = []
    ips_bloqueados = []
    
    for ip in ips_validos:
        protegido, cliente, range_ip = verificar_ip_em_excecoes(ip)
        
        if protegido:
            ips_bloqueados.append({
                "ip": ip,
                "cliente": cliente,
                "range": range_ip
            })
        else:
            ips_permitidos.append(ip)
    
    return ips_permitidos, ips_bloqueados

# Rotas de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error='Preencha usuário e senha')
        
        autenticado, tem_acesso, grupos, erro = verificar_grupo_ldap(username, password)
        
        if not autenticado:
            return render_template('login.html', error=erro)
        
        if not tem_acesso:
            return render_template('login.html', error=erro)
        
        # Cria usuário e faz login
        user = User(username, grupos)
        flask_session['user_groups'] = grupos
        login_user(user, remember=True)
        
        logging.info(f"Login bem-sucedido: {username}")
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    flask_session.clear()
    logging.info(f"Logout: {username}")
    return redirect(url_for('login'))

# Rotas principais (todas protegidas)
@app.route('/')
@login_required
def index():
    fortigates = ler_fortigates('fortigates.csv')
    return render_template('index.html', fortigates=fortigates, username=current_user.username)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/bloquear', methods=['POST'])
@login_required
def bloquear():
    try:
        data = request.json
        fortigate_id = int(data.get('fortigate_id'))
        group_name = data.get('group_name', 'IPs-Block')
        ips_str = data.get('ips', '')
        
        ips = list(set([ip.strip() for ip in ips_str.split(',') if ip.strip()]))
        ips_validos = [ip for ip in ips if validar_ip(ip)]
        
        if not ips_validos:
            return jsonify({"success": False, "message": "Nenhum IP válido informado"})
        
        ips_permitidos, ips_protegidos = validar_ips_contra_excecoes(ips_validos)

        if ips_protegidos:
            mensagens_erro = []
            for item in ips_protegidos:
                if item['cliente'] == '':
                    mensagens_erro.append(
                        f"{item['ip']}: Pertence ao range {item['range']} de IPs privados."
                    )
                else:
                    mensagens_erro.append(
                        f"{item['ip']}: Pertence ao range {item['range']} do cliente '{item['cliente']}'"
                    )
            
            return jsonify({
                "success": False,
                "message": "IPs protegidos detectados! Operação cancelada por segurança.",
                "protegidos": mensagens_erro
            })        
        
        fortigates = ler_fortigates('fortigates.csv')
        fortigate = fortigates[fortigate_id]
        ip_disponivel = verificar_ip_disponivel(fortigate)
        
        if not ip_disponivel:
            return jsonify({"success": False, "message": "Nenhum IP do Fortigate está disponível"})
        
        session_requests.headers.update({'Authorization': f"Bearer {fortigate['token']}"})
        
        resultados = []
        sucesso = 0
        falhas = 0
        
        for ip in ips_permitidos:
            result_add = add_address(ip, ip_disponivel["ip_completo"], current_user.username)
            
            if not result_add["success"]:
                falhas += 1
                resultados.append({
                    "ip": ip, 
                    "status": "erro", 
                    "message": f"❌ Falha ao criar address: {result_add['message']}"
                })
                continue
            
            grp_members = check_group_members(group_name, ip_disponivel["ip_completo"])
            
            if grp_members is None:
                falhas += 1
                resultados.append({
                    "ip": ip, 
                    "status": "erro", 
                    "message": f"✓ Address OK | ❌ Grupo não encontrado"
                })
                continue
            
            if any(member.get('name') == ip for member in grp_members):
                sucesso += 1
                resultados.append({
                    "ip": ip, 
                    "status": "ja_existe", 
                    "message": f"⚠ {result_add['message']} | ⚠ Já está no grupo"
                })
                continue
            
            members = grp_members + [{"name": ip}]
            result_group = add_member_to_group(group_name, ip_disponivel["ip_completo"], members)
            
            if result_group["success"]:
                sucesso += 1
                resultados.append({
                    "ip": ip, 
                    "status": "sucesso", 
                    "message": f"✓ {result_add['message']} | ✓ Adicionado ao grupo"
                })
            else:
                falhas += 1
                resultados.append({
                    "ip": ip, 
                    "status": "erro", 
                    "message": f"✓ Address OK | ❌ Falha no grupo: {result_group['message']}"
                })
        
        logging.info(f"Bloqueio por {current_user.username} - Fortigate: {fortigate['name']}, Sucesso: {sucesso}/{len(ips_permitidos)}")
        
        return jsonify({
            "success": True,
            "fortigate": fortigate['name'],
            "total": len(ips_permitidos),
            "sucesso": sucesso,
            "falhas": falhas,
            "resultados": resultados
        })
    except Exception as e:
        logging.error(f"Erro em bloquear por {current_user.username}: {e}")
        return jsonify({"success": False, "message": f"Erro: {str(e)}"})

@app.route('/remover', methods=['POST'])
@login_required
def remover():
    try:
        data = request.json
        fortigate_id = int(data.get('fortigate_id'))
        group_name = data.get('group_name', 'IPs-Block')
        ips_str = data.get('ips', '')
        
        ips = list(set([ip.strip() for ip in ips_str.split(',') if ip.strip()]))
        ips_validos = [ip for ip in ips if validar_ip(ip)]
        
        if not ips_validos:
            return jsonify({"success": False, "message": "Nenhum IP válido informado"})
        
        fortigates = ler_fortigates('fortigates.csv')
        fortigate = fortigates[fortigate_id]
        ip_disponivel = verificar_ip_disponivel(fortigate)
        
        if not ip_disponivel:
            return jsonify({"success": False, "message": "Fortigate inacessível"})

        session_requests.headers.update({'Authorization': f"Bearer {fortigate['token']}"})
        
        grp_members = check_group_members(group_name, ip_disponivel["ip_completo"])
        
        if grp_members is None:
            return jsonify({"success": False, "message": f"Grupo '{group_name}' não encontrado"})
        
        ips_no_grupo = [m.get('name') for m in grp_members]
        ips_para_remover = [ip for ip in ips_validos if ip in ips_no_grupo]
        
        resultados = []
        sucesso = 0
        
        if ips_para_remover:
            nova_lista = [m for m in grp_members if m.get('name') not in ips_para_remover]
            result_group = add_member_to_group(group_name, ip_disponivel["ip_completo"], nova_lista)
            
            if not result_group["success"]:
                return jsonify({
                    "success": False, 
                    "message": f"Erro ao atualizar grupo: {result_group['message']}"
                })
        
        for ip in ips_validos:
            estava_no_grupo = ip in ips_para_remover
            
            res_del = delete_address(ip, ip_disponivel["ip_completo"])
            
            if res_del["success"]:
                sucesso += 1
                if estava_no_grupo:
                    resultados.append({
                        "ip": ip, 
                        "status": "sucesso", 
                        "message": "✓ Removido do grupo | ✓ Address deletado"
                    })
                else:
                    resultados.append({
                        "ip": ip, 
                        "status": "warning", 
                        "message": "⚠ Não estava no grupo | ✓ Address deletado"
                    })
            else:
                resultados.append({
                    "ip": ip, 
                    "status": "erro", 
                    "message": f"{'✓ Removido do grupo' if estava_no_grupo else '⚠ Não estava no grupo'} | ❌ Falha ao deletar: {res_del['message']}"
                })

        logging.info(f"Remoção por {current_user.username} - Fortigate: {fortigate['name']}, Sucesso: {sucesso}/{len(ips_validos)}")

        return jsonify({
            "success": True,
            "fortigate": fortigate['name'],
            "total": len(ips_validos),
            "sucesso": sucesso,
            "falhas": len(ips_validos) - sucesso,
            "resultados": resultados
        })
    except Exception as e:
        logging.error(f"Erro em remover por {current_user.username}: {e}")
        return jsonify({"success": False, "message": str(e)})

@app.route('/verificar', methods=['POST'])
@login_required
def verificar():
    try:
        data = request.json
        fortigate_id = int(data.get('fortigate_id'))
        group_name = data.get('group_name', 'IPs-Block')
        ips_str = data.get('ips', '')
        
        ips = list(set([ip.strip() for ip in ips_str.split(',') if ip.strip()]))
        ips_validos = [ip for ip in ips if validar_ip(ip)]
        
        if not ips_validos:
            return jsonify({"success": False, "message": "Nenhum IP válido informado"})
        
        fortigates = ler_fortigates('fortigates.csv')
        fortigate = fortigates[fortigate_id]
        ip_disponivel = verificar_ip_disponivel(fortigate)
        
        if not ip_disponivel:
            return jsonify({"success": False, "message": "Fortigate inacessível"})

        session_requests.headers.update({'Authorization': f"Bearer {fortigate['token']}"})
        
        grp_members = check_group_members(group_name, ip_disponivel["ip_completo"])
        
        if grp_members is None:
            return jsonify({"success": False, "message": f"Grupo '{group_name}' não encontrado"})
        
        ips_no_grupo = [m.get('name') for m in grp_members]
        
        resultados = []
        encontrados = 0
        nao_encontrados = 0
        
        for ip in ips_validos:
            if ip in ips_no_grupo:
                encontrados += 1
                resultados.append({
                    "ip": ip,
                    "status": "encontrado",
                    "message": "✓ IP está no grupo"
                })
            else:
                nao_encontrados += 1
                resultados.append({
                    "ip": ip,
                    "status": "nao_encontrado",
                    "message": "⚠ IP não está no grupo"
                })
        
        logging.info(f"Verificação por {current_user.username} - Fortigate: {fortigate['name']}, Encontrados: {encontrados}/{len(ips_validos)}")
        
        return jsonify({
            "success": True,
            "fortigate": fortigate['name'],
            "group": group_name,
            "total": len(ips_validos),
            "sucesso": encontrados,
            "falhas": nao_encontrados,
            "resultados": resultados
        })
    except Exception as e:
        logging.error(f"Erro em verificar por {current_user.username}: {e}")
        return jsonify({"success": False, "message": str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5100)
