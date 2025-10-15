from get_feature import URLFeatureExtractor

def test_url(url):
    print(f"Analisando URL: {url}")
    extractor = URLFeatureExtractor(url)
    features = extractor.extract_all_features()
    
    # print("\nCaracterísticas extraídas:")
    # for feature, value in features.items():
    #     status = "PHISHING" if value == -1 else "SUSPEITO" if value == 0 else "LEGÍTIMO"
    #     print(f"{feature}: {value} ({status})")
    
    return features

# teste feature 1 having_ip_address:
def having_ip_address_test():
    url_com_ip = "https://192.168.1.1"
    url_sem_ip = "https://www.google.com"
    

    print("teste url com ip")
    value = test_url(url_com_ip)['having_ip_address']
    print(f"ok valor: {value}") if value == -1  else print(f"fail valor: {value}")
    print("teste url sem ip")
    value = test_url(url_sem_ip)['having_ip_address']
    print(f"ok valor: {value}") if value == 1  else print(f"fail valor: {value}")

# teste feature 2 url_length:
def url_length_test():
    url_length_long = "https://www.urlasjfnadlfasnflaksnlaksnflaskfnalsknfsafkdnfafasfafasfasfasfasfasfasfasfaflonga.com/"
    url_length_medium = "https://www.aoskfaosfaosfnaosifkansfkoaoskfaofaksfaosfaksfoasf.com/"
    url_length_short = "https://www.short.com/"
    
    print("teste url longa")
    value = test_url(url_length_long)['url_length']
    print(f"ok valor: {value}") if value == -1  else print(f"fail valor: {value}")
    print("teste url media")
    value = test_url(url_length_medium)['url_length']
    print(f"ok valor: {value}") if value == 0  else print(f"fail valor: {value}")
    print("teste url curta")
    value = test_url(url_length_short)['url_length']
    print(f"ok valor: {value}") if value == 1  else print(f"fail valor: {value}")

# teste feature 3 shortening_service:
def shortening_service_test():
    url_bitly = "https://bit.ly/whatever"
    url_goo = "https://goo.gl/whatever"
    url_tinyurl = "https://tinyurl.com/whatever"
    url_t = "https://t.co/whatever"
    url_ow = "https://ow.ly/whatever"
    url_is = "https://is.gd/whatever"
    url_buff = "https://buff.ly/whatever"
    url_adf = "https://adf.ly/whatever"
    url_bitdo = "https://bit.do/whatever"
    url_normal = "https://normal/whatever"

    print("teste url bit")
    value = test_url(url_bitly)['shortening_service']
    print(f"ok valor: {value}" ) if value == -1 else print (f"fail valor: {value}")

    print("teste url goo")
    value = test_url(url_goo)['shortening_service']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")

    print("teste url tinyurl") # t.co não consegue conexão 
    value = test_url(url_tinyurl)['shortening_service']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")

    print("teste url t") 
    value = test_url(url_t)['shortening_service']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")

    print("teste url ow")
    value = test_url(url_ow)['shortening_service']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")

    print("teste url is")
    value = test_url(url_is)['shortening_service']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")

    print("teste url buff")
    value = test_url(url_buff)['shortening_service']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")

    print("teste url adf")
    value = test_url(url_adf)['shortening_service']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")

    print("teste url bit")
    value = test_url(url_bitdo)['shortening_service']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")

    print("teste url normal")
    value = test_url(url_normal)['shortening_service']
    print(f"ok valor: {value}") if value == 1 else print (f"fail valor: {value}")   

# teste feature 4 having_at_symbol:
def having_at_symbol_test():
    url_with_at = "https://www.all@ficticious.com"
    url_no_at = "https://www.allficticious.com"

    print("teste url com @")
    value = test_url(url_with_at)['having_at_symbol']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")   
    
    print("teste url sem @")
    value = test_url(url_no_at)['having_at_symbol']
    print(f"ok valor: {value}") if value == 1 else print (f"fail valor: {value}")   

# teste feature 5 double_slash_redirecting:
def double_slash_redirecting_test():
    url_double_at_6 = "http://www.testdouble.com"
    url_double_at_7 = "https://www.testdouble.com"
    url_double_far = "https://www.testdouble.com//www.anothertest.com"

    print("teste // posição 6")
    value = test_url(url_double_at_6)['double_slash_redirecting']
    print(f"ok valor: {value}") if value == 1 else print (f"fail valor: {value}")    
    
    print("teste // posição 7")
    value = test_url(url_double_at_7)['double_slash_redirecting']
    print(f"ok valor: {value}") if value == 1 else print (f"fail valor: {value}")   
    
    print("teste // posição diferente de 6 ou 7")
    value = test_url(url_double_far)['double_slash_redirecting']
    print(f"ok valor: {value}") if value == -1 else print (f"fail valor: {value}")   


# teste feature 6 prefix_suffix:
def prefix_suffix_test():
    pass

# teste feature 7 having_sub_domain:
def having_sub_domain_test():
    pass

# teste feature 8 ssl_final_state:
def ssl_final_state_test():
    pass

# teste feature 9 domain_registration_length:
def domain_registration_length_test():
    pass

# teste feature 10 favicon:
def favicon_test():
    pass

# teste feature 11 port:
def port_test():
    pass

# teste feature 12 https_token:
def https_token_test():
    pass

# teste feature 13 request_url:
def request_url_test():
    pass

# teste feature 14 url_of_anchor:
def url_of_anchor_test():
    pass

# teste feature 15 links_in_tags:
def links_in_tags_test():
    pass

# teste feature 16 sfh:
def sfh_test():
    pass

# teste feature 17 submitting_to_email:
def submitting_to_email_test():
    pass

# teste feature 18 abnormal_url:
def abnormal_url_test():
    pass

# teste feature 19 redirect:
def redirect_test():
    pass

# teste feature 20 on_mouseover:
def on_mouseover_test():
    pass

# teste feature 21 right_click:
def right_click_test():
    pass

# teste feature 22 popup_window:
def popup_window_test():
    pass

# teste feature 23 iframe:
def iframe_test():
    pass

# teste feature 24 age_of_domain:
def age_of_domain_test():
    pass

# teste feature 25 dns_record:
def dns_record_test():
    pass

# teste feature 26 web_traffic:
def web_traffic_test():
    pass

# teste feature 27 page_rank:
def page_rank_test():
    pass

# teste feature 28 google_index:
def google_index_test():
    pass

# teste feature 29 links_pointing_to_page:
def links_pointing_to_page_test():
    pass

# teste feature 30 statistical_report:
def statistical_report_test():
    pass


################ chamada de testes individuais por feature #########################

print("teste having_ip_address_test")        
having_ip_address_test() #tudo ok

print("teste url_length")        
url_length_test() #tudo ok

print(" ")

print("teste shortening_service")
shortening_service_test() # tudo ok exceto "t.co" que não passa direito pelo extrator

print(" ")

print("teste having_at_symbol")
having_at_symbol_test() # tudo ok

print(" ")

print("teste double_slash_redirecting")
double_slash_redirecting_test() # tudo ok

# print(" ")

# print("teste prefix_suffix")
# prefix_suffix_test()

# print(" ")

# print("teste having_sub_domain")
# having_sub_domain_test()

# print(" ")

# print("teste ssl_final_state")
# ssl_final_state_test()

# print(" ")

# print("teste domain_registration_length")
# domain_registration_length_test()

# print(" ")

# print("teste favicon")
# favicon_test()

# print(" ")

# print("teste port")
# port_test()

# print(" ")

# print("teste https_token")
# https_token_test()

# print(" ")

# print("teste request_url")
# request_url_test()

# print(" ")

# print("teste url_of_anchor")
# url_of_anchor_test()

# print(" ")

# print("teste links_in_tags")
# links_in_tags_test()

# print(" ")

# print("teste sfh")
# sfh_test()

# print(" ")

# print("teste submitting_to_email")
# submitting_to_email_test()

# print(" ")

# print("teste abnormal_url")
# abnormal_url_test()

# print(" ")

# print("teste redirect")
# redirect_test()

# print(" ")

# print("teste on_mouseover")
# on_mouseover_test()

# print(" ")

# print("teste right_click")
# right_click_test()

# print(" ")

# print("teste popup_window")
# popup_window_test()

# print(" ")

# print("teste iframe")
# iframe_test()

# print(" ")

# print("teste age_of_domain")
# age_of_domain_test()

# print(" ")

# print("teste dns_record")
# dns_record_test()

# print(" ")

# print("teste web_traffic")
# web_traffic_test()

# print(" ")

# print("teste page_rank")
# page_rank_test()

# print(" ")

# print("teste google_index")
# google_index_test()

# print(" ")

# print("teste links_pointing_to_page")
# links_pointing_to_page_test()

# print(" ")

# print("teste statistical_report")
# statistical_report_test()

################ fim de chamada de testes individuais por feature ##################



# Exemplo de uso
# if __name__ == "__main__":
    # url = input()
    # features = test_url(url)
    
    # # Preparar para uso em um modelo (apenas os valores)
    # feature_vector = list(features.values())
    # print(f"\nVetor de características para o modelo: {feature_vector}")

    # print(features)

"""
features
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

"""