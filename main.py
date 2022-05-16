from secrets import choice
from menu import menu
from RSA_key_gen import key_gen, AES_key_gen, key_pair
from utility import from_bytes, to_bytes
from entity import person

extensao = ".crypt"

def generate_RSA_key():

    print("Gerando chaves, com primos de 1024 bits...")
    keys = key_gen().generate_key(bit_size=2048)

    print("Chaves geradas\n")
    print(f"Modulo n: {keys.n}")
    print(f"Chave publica: {keys.e}")
    print(f"Chave privada: {keys.d}\n")

    print("Primos gerados")
    print(f"p = {keys.p}")
    print(f"q = {keys.q}\n")

    print("Obs: anote e guarde a chave gerada, essa é a única chance pra isso!")
    input("Digite enter para continuar...")
    menu.clear_output()

def get_key(file_name):

    choice = menu(options=[("S", lambda: True), ("N", lambda: False)], init_msg="Usar chave pré-definida?").execute()

    if choice == True:
        try:
            file = open(file_name)
        except:
            file = open(file_name, mode='wt+')
            print("Chaves nao existem, gerando novas...")

            kp = key_gen().generate_key(bit_size=2048)

            info = vars(kp)

            file.write(info.__str__())

            file.close()

            file = open(file_name)

        
        my_key = key_pair()

        info = dict(eval(file.read()))

        my_key.__dict__ = info

        file.close()


    else:
        my_n = my_e = my_d = 0
        try:
            my_n = int(input("Digite o modulo n: "))
        except:
            pass
        try:
            my_e = int(input("Digite a chave publica: "))
        except:
            pass
        try:
            my_d = int(input("Digite a chave privada: "))
        except:
            pass

        my_key = key_pair()
        my_key.set_public(my_n, my_e)
        my_key.set_private(n=my_n, d=my_d)

    return my_key
    

def write_message():
    
    msg = input("Qual a sua mensagem? ")
    msg = to_bytes(msg)

    # file_name= input("Qual o nome do arquivo? ")
    # file_name = input_file + extensao
    file_name = input("Digite o nome do arquivo em que será gravada a mensagem: ")

    # try:
    #     # input_file = input_file.strip('\"\' ')
    #     with open(file_name, mode='rb') as f:
    #         msg = f.read()

    # except:
    #     print("Impossivel abrir o arquivo!")
    #     print("Encerrando o programa...")
    #     exit(1)


    print("\n----- Inserindo a sua chave RSA -----")
    print("Digite apenas o modulo n e a chave privada, caso seja requisitado")
    my_key = get_key("RSA_keys01.txt")

    
    print("----- Inserindo chave publica RSA do recebedor -----")
    print("Digite apenas o modulo n e a chave publica dele, caso seja requisitado!")
    receptor_key = get_key("RSA_keys02.txt")
    
    eu = person(my_key)

    public = (receptor_key.n, receptor_key.e)

    eu.send_msg(msg, public, file_name)
    print(f"Mensagem escrita! Abra o arquivo {file_name} para verificar.")

def read_message():

    try:
        file_name = input("Digite o nome do arquivo a ser lido: ")
        # file_name = input(f"Digite o nome do arquivo a ser lido (com extensao {extensao}): ")
        # file_name = file_name.strip('\"\' ')
        open(file_name).close()
    except:
        print("Impossivel abrir o arquivo!")
        print("Encerrando o programa...")
        exit(1)


    print("\n----- Inserindo a sua chave RSA -----")
    print("Digite apenas o modulo n e a chave privada, caso seja requisitado!")
    
    k = get_key("RSA_keys02.txt")
    my_n, my_d = k.n, k.d

    print("\n----- Inserindo chave publica RSA do remetente -----")
    print("Digite apenas o modulo n e a chave publica dele, caso seja requisitado!")
    k = get_key("RSA_keys01.txt")
    n, e = k.n, k.e

    sender_key = (n, e)
    kp = key_pair()
    kp.set_private(n=my_n, d=my_d)

    eu = person(kp)

    sign, msg = eu.receive_msg(sender_key, file_name)
    msg = from_bytes(msg)

    # file_name = "decrypt_"+file_name.replace(extensao, '')

    # f = open(file_name, mode="wb")
    # f.write(msg)
    # f.close()

    # print("Arquivo com o dado:", file_name)
    print("Assinatura bate?", sign)
    print("Mensagem recebida: ", msg)

def generate_AES_key():

    bit_size = int(input("Quantos bits na chave? Escolha entre 128, 192 e 256. "))

    key = AES_key_gen(bit_size).generate_key()

    print(f"Chave de {AES_key_gen(bit_size).bit_size} bits gerada:")
    print(key,'\n')

    print("Obs: anote e guarde a chave gerada, essa é a única chance pra isso!")
    input("Digite enter para continuar...")

    menu.clear_output()

def main():

    options=[   ("Gerar chave assimetrica (RSA)", generate_RSA_key),
                ("Gerar chave simetrica (AES)", generate_AES_key), 
                ("Escrever mensagem", write_message),
                ("Receber mensagem", read_message)]

    msg = "Bom dia"

    main_menu = menu(options, choice_msg = "Escolha uma opcao", init_msg = msg)

    main_menu.execute()

main()