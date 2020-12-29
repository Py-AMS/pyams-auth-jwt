��          �   %   �      0     1     G  #   Y  J   }     �  %   �       $  "     G     Y     p     �  &   �  
   �     �     �  3   �  3     1   Q  �   �  9   6  1   p  A   �  C  �  !   (      J  <   k  q   �  $   	  2   ?	     r	  �  �	     I     [     s     �  :   �     �  #   �     �  I     H   ^  I   �  �   �  W   �  J     a   ^                                                                                     	      
                                    Access token lifetime Enable JWT login? Enable login via JWT authentication HS* protocols are using the secret, while RS* protocols are using RSA keys Invalid credentials! JWT access token lifetime, in seconds JWT authentication credentials JWT authentication module provides features and a REST API which can be used to generate, refresh and verify access tokens.
You can choose to use a simple secret key to encrypt your tokens, or to use a private and a public keys (which can to be used to share tokens between two applications)
 JWT configuration JWT encoding algorithm JWT private key JWT public key JWT refresh token lifetime, in seconds JWT secret Refresh token lifetime Security manager The public key is required when using RS* algorithm The secret key is required when using RS* algorithm This secret is required when using HS* encryption You can use the `openssl` command to generate your keys:

    openssl genpkey -algorithm RSA -out private-key.pem
    openssl rsa -pubout -in private-key.pem -out public-key.pem
 You must choose an algorithm to enable JWT authentication You must define JWT secret to use HS256 algorithm You must define a private and a public key to use RS256 algorithm Project-Id-Version: PACKAGE 1.0
POT-Creation-Date: 2020-12-29 11:27+0100
PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE
Last-Translator: FULL NAME <EMAIL@ADDRESS
Language-Team: LANGUAGE <LL@li.org>
Language: 
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Generated-By: Lingua 3.10.dev0
 Durée de vie des tokens d'accès Activer l'authentification JWT ? Activer la connexion via une authentification par tokens JWT Les protocoles de type HS utilisent le code secret, tandis que les protocoles de types RS utilisent les clés RSA Paramètres de connexion invalides ! Durée de vie des tokens d'accès JWT, en secondes Authentification JWT Le module d'authentification JWT fournit des fonctionnalités ainsi qu'une API REST qui peuvent être utilisées pour générer, rafraîchir et vérifier des jetons JWT.
Vous pouvez utiliser un simple secret pour encrypter les tokens, ou utiliser un couple de clés publique et privée (qui peuvent notamment être utilisées pour partager des jetons entre plusieurs applications qui peuvent s'appuyer sur une autorité d'authentification commune).
 Configuration JWT Algorithme d'encryptage Clé privée Clé publique Durée de vie des tokens de rafraîchissement, en secondes Code secret Durée de vie des tokens de refresh Gestionnaire de sécurité Une clé publique est nécessaire pour utiliser un encryptage de type RS* Une clé privée est nécessaire pour utiliser un encryptage de type RS* Ce code secret est nécessaire si vous utilisez un encryptage de type HS* Vous pouvez utiliser la commande `openssl` pour générer vos clés :

         openssl genpkey -algorithm RSA -out private-key.pem
         openssl rsa -pubout -in private-key.pem -out public-key.pem
 Vous devez sélectionner un algorithme d'encryptage pour activer l'authentification JWT Vous devez définir un code secret pour utiliser un encryptage de type HS* Vous devez définir une clé privée et une clé publique pour utiliser un encryptage de type RS* 