#
# Référence : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
#


# 
# Definition de constantes 'H'. 
#
#  Ce sont les 32 premiers bits de la partie décimale de la racine carrée des nombres premiers compris entre 2 et 19.
#

H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# 
# Definition de constantes 'K'. 
#
#  Ce sont les 32 premiers bits de la partie décimale de la racine cubique des nombres premiers compris entre 2 et 311.
#

K = [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

print(H)
print(K)

# -------------------------------------------    
def lire_fichier_binaire(nom_fichier):
# -------------------------------------------    

   '''
      Lecture d'un fichier quelconque en entrée, au format binaire
   '''
    
   with open(nom_fichier, 'rb') as file:
        return file.read()


# -------------------------------------------    
def padding_message(message):
# -------------------------------------------    

   '''
      Padding du message
   '''

   message_bits = ''.join(f'{byte:08b}' for byte in message)
   original_length = len(message_bits)

   # Ajouter un '1' à la fin du message
   message_bits += '1'

   # Ajouter des zéros jusqu'à ce que la longueur soit congrue à 448 bits modulo 512
   while len(message_bits) % 512 != 448:
      message_bits += '0'

   # Ajouter la longueur originale du message sur 64 bits à la fin
   message_bits += f'{original_length:064b}'

   return message_bits


# -------------------------------------------    
def decoupage_blocs(message_bits, block_size=512):
# -------------------------------------------    

   '''
      Découpage en blocs
   '''
   return [message_bits[i:i + block_size] for i in range(0, len(message_bits), block_size)]


# -------------------------------------------    
def rotR(x, n):
# -------------------------------------------    

   '''
      Rotation droite de x par n bits.
   '''

   return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF


# -------------------------------------------    
def prepare_message_schedule(block):
# -------------------------------------------    

   '''
      Prépare le message étendu de 64 mots pour un bloc de 512 bits.
   '''

   # w[0..15] = les mots de 32 bits du bloc actuel
   w = [0] * 64
   for i in range(16):
      w[i] = int.from_bytes(block[i * 4:(i + 1) * 4], 'big')

   # Calcul des mots w[16..63]
   for i in range(16, 64):
      sig0 = rotR(w[i-15], 7) ^ rotR(w[i-15], 18) ^ (w[i-15] >> 3)
      sig1 = rotR(w[i-2], 17) ^ rotR(w[i-2], 19) ^ (w[i-2] >> 10)
      w[i] = (w[i-16] + sig0 + w[i-7] + sig1) & 0xFFFFFFFF

   return w


# -------------------------------------------    
def main(filename):
# -------------------------------------------    

   message = lire_fichier_binaire(filename)
   padded_message_bits = padding_message(message)
   blocks = decoupage_blocs(padded_message_bits)

   # Initialisation des variables de travail avec les racines carrées de H
   a, b, c, d, e, f, g, h = H

   print(f"Nombre total de blocs de 512 bits : {len(blocks)}")
   for i, block in enumerate(blocks):
      print(f"Bloc {i+1} : {block}")



# -------------------------------------------    
#     main()
# -------------------------------------------    
if __name__ == "__main__":
   filename = "test.bin"  # Remplacez par le nom de votre fichier
   main(filename)
