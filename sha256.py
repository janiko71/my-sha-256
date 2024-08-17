#
# Référence : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
#

#
# Ce programme n'ayant qu'un objectif d'illuster le fonctionnement de l'algorithme de hachage SHA256, il n'est pas optimisé.
#
# En particulier, les objets et variables intermédiaires sont parfois stockés sous forme de chaînes de caractères, pour permettre
# un affichage plus simple à certaines étapes du traitement, grâce à la bibliothèque 'bitstring'.
#

#
# Imports
#

import bitstring

# 
# Definition de la constante 'H'. Servira de base pour le hash initial 
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

   message_bits = bitstring.BitArray(bytes=message)
   original_length = len(message_bits)

   # Ajouter un '1' à la fin du message
   message_bits.append('0x1')

   # Ajouter des zéros jusqu'à ce que la longueur soit congrue à 448 bits modulo 512
   while len(message_bits) % 512 != 448:
      message_bits.append('0x0')

   # Ajouter la longueur originale du message sur 64 bits à la fin
   message_bits.append(bitstring.Bits(int64=original_length))

   return message_bits


# -------------------------------------------    
def decoupage_blocs(message_bits, block_size=512):
# -------------------------------------------    

   '''
      Découpage en blocs
   '''
   return [message_bits[i:i + block_size] for i in range(0, len(message_bits), block_size)]


# -------------------------------------------    
def addition_32bits(a, b):
# -------------------------------------------    

    # Convertir les entiers en BitArray de 32 bits
    #a_bits = BitArray(a, length=32)
    #b_bits = BitArray(b, length=32)
    
    # Effectuer l'addition
    result = a.uint + b.uint
    
    # Appliquer un masque pour s'assurer que le résultat reste sur 32 bits
    result_32bits = result & 0xFFFFFFFF
    
    # Retourner le résultat en tant que BitArray de 32 bits
    return bitstring.BitArray(uint=result_32bits, length=32)


# -------------------------------------------    
def prepare_message_schedule(block):
# -------------------------------------------    

   '''
      Prépare le message étendu de 64 mots pour un bloc de 512 bits.
   '''

   # w[0..15] = les mots de 32 bits du bloc actuel

   w = [0] * 64
   for i in range(16):
      w[i] = block[i * 32:(i + 1) * 32]

   # Calcul des mots supplémentaires w[16..63], qui font chacun 32 bits, avec des "rétroactions"

   for i in range(16, 64):
      
      # Sigma 0 : rotation droite sur 7 bits de w[i-15] ⊕ rotation droite sur 18 bits de [i-15] ⊕ décalage à droite sur 3 bits de [i-15], ⊕ désignant le OU EXCLUSIF
      # Le type Bits est invariable, on recrée un BitArray qui lui est variable ("mutable") pour ne pas modifier la valeur originale de w[i-15] dans ce calcul.
      # Le 'ror' de 'bitstring' modifie la donnée passée en paramètre.

      terme_1 = bitstring.BitArray(w[i-15])
      terme_1.ror(7)

      terme_2 = bitstring.BitArray(w[i-15])
      terme_2.ror(18)

      sig0 = terme_1 ^ terme_2 ^ (bitstring.BitArray(w[i-15]) >> 3)

      # Sigma 0 : rotation droite sur 17 bits de w[i-2] ⊕ rotation droite sur 19 bits de [i-2] ⊕ décalage à droite sur 10 bits de [i-2], ⊕ désignant le OU EXCLUSIF
      # Ici aussi on recrée un BitArray qui lui est variable ("mutable") pour ne pas modifier la valeur originale de w[i-15] dans ce calcul

      terme_1 = bitstring.BitArray(w[i-2])
      terme_1.ror(17)

      terme_2 = bitstring.BitArray(w[i-2])
      terme_2.ror(19)

      sig1 = terme_1 ^ terme_2 ^ (bitstring.BitArray(w[i-2]) >> 10)

      result = (bitstring.BitArray(w[i-16]) + sig0 + bitstring.BitArray(w[i-7]) + sig1)
      w[i] = result

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
      # w = prepare_message_schedule(block)

   print("-"*32)

   #my_block = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"   
   my_block = bitstring.Bits(bin="11000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011")
   w = prepare_message_schedule(my_block)
   #print(w)

   print("-"*32)

   test_a = bitstring.BitArray(bin="11000000000000000001100100010100", length=32)
   test_b = bitstring.BitArray(bin="11100101110101010100000100010101", length=32)
   print(addition_32bits(test_a, test_b).bin)


# -------------------------------------------    
#     main()
# ------------------------------------------- 

if __name__ == "__main__":
   filename = "test.bin"  # Remplacez par le nom de votre fichier
   main(filename)
