import requests
from urllib.parse import urlparse
import tldextract
import re
import ssl
import socket
import whois
from datetime import datetime
import time
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings('ignore')

class URLFeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.extracted = tldextract.extract(url)
        self.domain = f"{self.extracted.domain}.{self.extracted.suffix}"
        self.features = {}
        
        # Headers para simular um navegador
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            self.response = requests.get(url, headers=self.headers, timeout=10, verify=False)
            self.soup = BeautifulSoup(self.response.content, 'html.parser')
        except:
            self.response = None
            self.soup = None
    
    def having_ip_address(self):
        """Feature 1: Verifica se a URL contém um endereço IP"""
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        match = re.search(ip_pattern, self.url)
        return -1 if match else 1  # -1 para phishing, 1 para legítimo
    
    def url_length(self):
        """Feature 2: Comprimento da URL"""
        length = len(self.url)
        if length < 54:
            return 1  # Legítimo
        elif 54 <= length <= 75:
            return 0   # Suspeito
        else:
            return -1   # Phishing
    
    def shortening_service(self):
        """Feature 3: Verifica se é um serviço de encurtamento de URL"""
        shortening_domains = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do']
        return -1 if any(domain in self.url for domain in shortening_domains) else 1
    
    def having_at_symbol(self):
        """Feature 4: Verifica se contém o símbolo @"""
        return -1 if '@' in self.url else 1
    
    def double_slash_redirecting(self):
        """Feature 5: Verifica redirecionamento usando '//' (posição da última ocorrência)"""
        last_double_slash = self.url.rfind("//")
        
        if self.url.startswith("http://"):
            return -1 if last_double_slash > 6 else 1
        elif self.url.startswith("https://"):
            return -1 if last_double_slash > 7 else 1
        else:
            return 1
    
    def prefix_suffix(self):
        """Feature 6: Verifica se há hífen no domínio"""
        return -1 if '-' in self.extracted.domain else 1
    
    def having_sub_domain(self):
        """Feature 7 (corrigida): conta subdomínios conforme o paper"""
        subdomain = self.extracted.subdomain
        
        if subdomain.startswith("www."):
            subdomain = subdomain[4:]
        elif subdomain == "www":
            subdomain = ""
        
        num_dots = subdomain.count('.')
        
        if num_dots == 0:
            return 1   
        elif num_dots == 1:
            return 0   
        else:
            return -1
    
    def ssl_final_state(self):
        """Feature 8: Verifica estado do certificado SSL"""
        try:
            hostname = self.parsed_url.hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Verifica se o certificado é válido
                    return 1  # Válido (legítimo)
        except:
            return -1  # Inválido (phishing)
    
    def domain_registration_length(self):
        """Feature 9: Verifica tempo de registro do domínio"""
        try:
            domain_info = whois.whois(self.domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                # Domínios registrados há mais de 1 ano são considerados mais confiáveis
                age = (datetime.now() - creation_date).days
                return 1 if age >= 365 else -1
        except:
            pass
        
        return 0  # Não foi possível verificar
    
    def favicon(self):
        """Feature 10: Verifica se o favicon está no mesmo domínio"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            favicon = self.soup.find('link', rel='icon') or self.soup.find('link', rel='shortcut icon')
            if favicon and 'href' in favicon.attrs:
                favicon_url = favicon['href']
                if favicon_url.startswith('http'):
                    parsed_favicon = urlparse(favicon_url)
                    return 1 if parsed_favicon.netloc == self.parsed_url.netloc else -1
                else:
                    return 1  # Favicon relativo (mesmo domínio)
            return 0  # Não encontrado
        except:
            return 0  # Erro na verificação
    
    def port(self):
        """Feature 11: Verifica porta não padrão"""
        if self.parsed_url.port:
            if self.parsed_url.port not in [80, 443]:
                return -1  # Porta não padrão (phishing)
        return 1  # Porta padrão ou não especificada (legítimo)
    
    def https_token(self):
        """Feature 12: Verifica se 'https' está no domínio"""
        return -1 if 'https' in self.extracted.domain else 1
    
    def request_url(self):
        """Feature 13: Percentual de recursos externos"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            total_tags = len(self.soup.find_all(['img', 'video', 'audio', 'source']))
            if total_tags == 0:
                return 0
            
            external = 0
            for tag in self.soup.find_all(['img', 'video', 'audio', 'source']):
                if tag.get('src') and not tag['src'].startswith(('data:', 'about:')):
                    parsed_src = urlparse(tag['src'])
                    if parsed_src.netloc and parsed_src.netloc != self.parsed_url.netloc:
                        external += 1
            
            percentage = (external / total_tags) * 100
            
            if percentage < 22:
                return 1  # Legítimo
            elif 22 <= percentage <= 61:
                return 0  # Suspeito
            else:
                return -1  # Phishing
        except:
            return 0  # Erro na verificação
    
    def url_of_anchor(self):
        """Feature 14: Percentual de âncoras externas"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            anchors = self.soup.find_all('a', href=True)
            if not anchors:
                return 0
            
            external = 0
            for anchor in anchors:
                href = anchor['href']
                if href.startswith(('http', 'www')):
                    parsed_href = urlparse(href)
                    if parsed_href.netloc and parsed_href.netloc != self.parsed_url.netloc:
                        external += 1
            
            percentage = (external / len(anchors)) * 100
            
            if percentage < 31:
                return 1  # Legítimo
            elif 31 <= percentage <= 67:
                return 0  # Suspeito
            else:
                return -1  # Phishing
        except:
            return 0  # Erro na verificação
    
    def links_in_tags(self):
        """Feature 15: Links em tags (meta, script e link)"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            tags = self.soup.find_all(['meta', 'script', 'link'])
            external = 0
            total = 0
            
            for tag in tags:
                for attr in ['src', 'href', 'content']:
                    if tag.get(attr):
                        url_value = tag[attr]
                        if url_value.startswith('http'):
                            parsed_url = urlparse(url_value)
                            if parsed_url.netloc and parsed_url.netloc != self.parsed_url.netloc:
                                external += 1
                        total += 1
            
            if total == 0:
                return 0
                
            percentage = (external / total) * 100
            
            if percentage < 17:
                return 1  # Legítimo
            elif 17 <= percentage <= 81:
                return 0  # Suspeito
            else:
                return -1  # Phishing
        except:
            return 0  # Erro na verificação
    
    def sfh(self):
        """Feature 16: Verifica action de formulários"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            forms = self.soup.find_all('form')
            if not forms:
                return 1  # Não há formulários, considerado legítimo
            
            for form in forms:
                action = form.get('action', '')
                if not action or action == 'about:blank':
                    return -1  # Phishing
                elif not action.startswith('http'):
                    return 0  # Suspeito
            
            return 1  # Todos os formulários têm action válida
        except:
            return 0  # Erro na verificação
    
    def submitting_to_email(self):
        """Feature 17: Verifica se formulário envia para email"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            forms = self.soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if 'mailto:' in action.lower():
                    return -1  # Phishing
            
            return 1  # Legítimo
        except:
            return 0  # Erro na verificação
    
    def abnormal_url(self):
        """Feature 18: Verifica se o hostname está na URL"""
        if self.parsed_url.hostname and self.parsed_url.hostname in self.url:
            return 1  # Legítimo
        return -1  # Phishing
    
    def redirect(self):
        """Feature 19: Verifica redirecionamento"""
        try:
            if self.response and len(self.response.history) > 1:
                return -1  # Múltiplos redirecionamentos (phishing)
            return 1  # Sem redirecionamentos múltiplos (legítimo)
        except:
            return 0  # Erro na verificação
    
    def on_mouseover(self):
        """Feature 20: Verifica eventos onMouseover"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            scripts = str(self.soup).lower()
            return -1 if 'onmouseover' in scripts and 'window.status' in scripts else 1
        except:
            return 0  # Erro na verificação
    
    def right_click(self):
        """Feature 21: Verifica se right-click está desabilitado"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            scripts = str(self.soup).lower()
            return -1 if 'event.button==2' in scripts or 'contextmenu' in scripts else 1
        except:
            return 0  # Erro na verificação
    
    def popup_window(self):
        """Feature 22: Verifica pop-ups"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            scripts = str(self.soup).lower()
            return -1 if 'window.open' in scripts and 'alert' not in scripts else 1
        except:
            return 0  # Erro na verificação
    
    def iframe(self):
        """Feature 23: Verifica iframes"""
        if not self.soup:
            return 0  # Não foi possível verificar
        
        try:
            iframes = self.soup.find_all('iframe')
            return -1 if iframes else 1
        except:
            return 0  # Erro na verificação
    
    def age_of_domain(self):
        """Feature 24: Idade do domínio"""
        try:
            domain_info = whois.whois(self.domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age = (datetime.now() - creation_date).days
                # Domínios com mais de 6 meses são considerados mais confiáveis
                return 1 if age >= 180 else -1
        except:
            pass
        
        return 0  # Não foi possível verificar
    
    def dns_record(self):
        """Feature 25: Verifica registro DNS"""
        try:
            socket.gethostbyname(self.domain)
            return 1  # DNS record existe (legítimo)
        except:
            return -1  # DNS record não existe (phishing)
    
    def web_traffic(self):
        """Feature 26: Tráfego web (simplificado)"""
        # Esta feature normalmente exigiria uma API como Alexa
        # Retornando valor neutro por padrão
        return 0
    
    def page_rank(self):
        """Feature 27: PageRank (simplificado)"""
        # Esta feature normalmente exigiria uma API
        # Retornando valor neutro por padrão
        return 0
    
    def google_index(self):
        """Feature 28: Verifica se está indexado no Google"""
        # Esta feature normalmente exigiria uma API do Google
        # Retornando valor neutro por padrão
        return 0
    
    def links_pointing_to_page(self):
        """Feature 29: Links apontando para a página"""
        # Esta feature normalmente exigiria uma API
        # Retornando valor neutro por padrão
        return 0
    
    def statistical_report(self):
        """Feature 30: Relatório estatístico"""
        # Esta feature normalmente exigiria verificação em blacklists
        # Retornando valor neutro por padrão
        return 0
    
    def extract_all_features(self):
        """Extrai todas as features"""
        methods = [
            'having_ip_address',
            'url_length',
            'shortening_service',
            'having_at_symbol',
            'double_slash_redirecting',
            'prefix_suffix',
            'having_sub_domain',
            'ssl_final_state',
            'domain_registration_length',
            'favicon',
            'port',
            'https_token',
            'request_url',
            'url_of_anchor',
            'links_in_tags',
            'sfh',
            'submitting_to_email',
            'abnormal_url',
            'redirect',
            'on_mouseover',
            'right_click',
            'popup_window',
            'iframe',
            'age_of_domain',
            'dns_record',
            'web_traffic',
            'page_rank',
            'google_index',
            'links_pointing_to_page',
            'statistical_report',
        ]
        #methods = [method for method in dir(self) if not method.startswith('_') and method not in ['url', 'parsed_url', 'extracted', 'domain', 'features', 'headers', 'response', 'soup', 'extract_all_features']]
        # dir(self) lista os metodos desse arquivo em ordem alfabética, dessa forma o vetor de features tambem será criado em ordem alfabética
        # e isso não é o que queremos

        

        for method in methods:
            try:
                self.features[method] = getattr(self, method)()
            except Exception as e:
                print(f"Erro ao extrair feature {method}: {str(e)}")
                self.features[method] = 0  # Valor neutro em caso de erro
        
        return self.features

# Função para testar uma URL
def test_url(url):
    print(f"Analisando URL: {url}")
    extractor = URLFeatureExtractor(url)
    features = extractor.extract_all_features()
    
    print("\nCaracterísticas extraídas:")
    for feature, value in features.items():
        status = "PHISHING" if value == -1 else "SUSPEITO" if value == 0 else "LEGÍTIMO"
        print(f"{feature}: {value} ({status})")
    
    return features

# Exemplo de uso
if __name__ == "__main__":
    # Teste com uma URL (substitua por qualquer URL que desejar testar)
    url = input()
    features = test_url(url)
    
    # Preparar para uso em um modelo (apenas os valores)
    feature_vector = list(features.values())
    print(f"\nVetor de características para o modelo: {feature_vector}")