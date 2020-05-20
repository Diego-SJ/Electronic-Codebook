from io import open
import os
import re
from cmd import Cmd
import binaryEncryptionMethods as Bem
import manageFile as mf
os.system('clear')

# ! MAIN CLASS
class electronicCB(Cmd):
    def __init__(self):
        super().__init__()
        try:
            plainTextClean = mf.readFile('PlainText.txt','a')
        except LookupError:
            print('ERROR: File error.')
        else:
            self.plainText = plainTextClean
            bytearray(self.plainText, 'utf8')

        # * Read configFile.txt
        try:
            with open("configFile.txt","r") as configFile:
                for variables in configFile:
                    v1 = re.match(r".*accion: ([a-z]*)",variables)
                    if v1:
                        accion = (v1.group(1))
                        if accion == 'e' or accion == 'd':
                            pass
                        else:
                            print(f'ERROR: acción de encriptado invalido.')
                            exit()
                    v2 = re.match(r".*metodo: ([1-3]*)",variables)
                    if v2:
                        metodo = (v2.group(1))
                        if metodo == '1' or metodo == '2' or metodo == '3':
                            pass
                        else:
                            print(f'ERROR: método invalido.')
                            exit()

                    v2 = re.match(r".*llave: ([-0-9]*)",variables)
                    if v2:
                        llaveg = (v2.group(1))

            if metodo == '1':
                if len(llaveg) == 8:
                    try:bytearray(int(llaveg, 2))
                    except:
                        print(f'ERROR: la llave no es binaria.')
                        exit()
                else:
                    print(f'ERROR: la llave debe ser 8 bits.')
                    exit()
            if metodo == '2':
                alphabet = "12345678"
                if len(llaveg) != len(alphabet):
                    print("ERROR: la llave debe ser 8 bits.")
                    exit()
                flag = 0
                for k in llaveg:
                    repeat = 0
                    for l in llaveg:
                        if l in alphabet:
                            if k == l:
                                repeat += 1
                        else:
                            flag += 1
                        if repeat > 1:
                            flag += 1
                if flag >= 1:
                    print("\nERROR! A key number is repeated or is invalid.")
                    exit()
            if metodo == '3':
                try:
                    alphaBin = '-01'
                    for i in llaveg:
                        if i not in alphaBin:
                            print(f'ERROR: la llave no es binaria.')
                            exit()
                except:
                    print(f'ERROR: la llave no es binaria.')
                    exit()
        except LookupError:
            print('ERROR: read config file.')
        else:
            self.Metodo = metodo
            self.LlaveM = llaveg
            if accion == 'e':
                self.encrypt(llaveg)
            elif accion == 'd':
                self.decrypt(llaveg)
            else:
                exit()
        # * --------------------

    def encrypt(self, KEY):
        try:
            # * Check the key
            if self.Metodo == '1':
                bytearray(int(KEY, 2))
                if len(KEY) != 8:
                    print(f'ERROR: The key is not an 8 bit binary number.')
                    exit()
            elif self.Metodo == '2':
                pass
            elif self.Metodo == '3':
                pass
            # * -------------
            octetos = bytearray(self.plainText, 'utf8')
        except:
            print(f'ERROR: The key is not an 8 bit binary number.')
        else:
            bytesArray = (' '.join(f'{x:b}'.rjust(8, '0') for x in octetos)).split()
            cipherText = ''
            logProcess = '----- log -----\n'
            i = 0
            for ba in bytesArray:
                i += 1
                # * Choose a method
                if self.Metodo == '1':
                    cc = Bem.CesarE(ba,self.LlaveM)
                    cipherText += cc + ' '
                    logProcess += ('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'\
                    '\nP{} -> {}'\
                    '\n        cesar ------> C{} -> {}'\
                    '\nK  -> {}').format(i,ba,i,cc,KEY)
                if self.Metodo == '2':
                    cc = Bem.MonoE(ba,self.LlaveM)
                    cipherText += cc + ' '
                    logProcess += ('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'\
                    '\nP{} -> {}'\
                    '\n        mono ------> C{} -> {}'\
                    '\nK  -> {}').format(i,ba,i,cc,KEY)
                if self.Metodo == '3':
                    cc = Bem.DispE(ba,self.LlaveM)
                    cipherText += cc + ' '
                    logProcess += ('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'\
                    '\nP{} -> {}'\
                    '\n        disp ------> C{} -> {}'\
                    '\nK  -> {}').format(i,ba,i,cc,KEY)
                # * ---------------
            mf.createFile('cipherText.txt',cipherText)
            mf.createFile('log.txt',logProcess+'\n\nRESULT:\n'+cipherText)
            print('\nCOMPLETED PROCESS\n')
        exit()

    def decrypt(self, KEY):
        try:
            # * Check the key
            if self.Metodo == '1':
                bytearray(int(KEY, 2))
                if len(KEY) != 8:
                    print(f'ERROR: The key is not an 8 bit binary number.')
                    exit()
            elif self.Metodo == '2':
                pass
            elif self.Metodo == '3':
                pass
            # * --------------
            plainTextClean = mf.readFile('cipherText.txt','b')
            bytearray(int(x, 2) for x in plainTextClean.split())
        except:
            print('ERROR: It is not a binary string.')
            exit()

        plainText = ''
        finalText = ''
        logProcess = '----- log D -----\n'
        i = 0
        for o in plainTextClean.split():
            i += 1
            # * Choose a method
            if self.Metodo == '1':
                cc = Bem.CesarD(o,self.LlaveM)
                plainText += cc + ' '
                logProcess += ('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'\
                '\nC{} -> {}'\
                '\n        cesar ------> P{} -> {} = {}'\
                '\nK  -> {}').format(i,o,i,cc,chr(int(cc, 2)),KEY)
            if self.Metodo == '2':
                cc = Bem.MonoD(o,self.LlaveM)
                plainText += cc + ' '
                logProcess += ('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'\
                '\nC{} -> {}'\
                '\n        mono ------> P{} -> {} = {}'\
                '\nK  -> {}').format(i,o,i,cc,chr(int(cc, 2)),KEY)
            if self.Metodo == '3':
                cc = Bem.DispD(o,self.LlaveM)
                plainText += cc + ' '
                logProcess += ('\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'\
                '\nC{} -> {}'\
                '\n        disp ------> P{} -> {} = {}'\
                '\nK  -> {}').format(i,o,i,cc,chr(int(cc, 2)),KEY)
            # * ---------------
        finalText = ''.join([chr(int(b, 2)) for b in plainText.split()])
        mf.createFile('decryptText.txt','DECRYPT TEXT:\n'+plainText+'\n\nFINAL PLAIN TEXT:\n'+finalText)
        mf.createFile('log.txt',logProcess+'\n\nRESULT:\n'+finalText)
        print('\nCOMPLETED PROCESS\n')
        exit()

app = electronicCB()
app.cmdloop()