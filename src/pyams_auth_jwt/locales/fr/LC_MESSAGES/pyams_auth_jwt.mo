��    3      �  G   L      h     i     �     �  v   �  /   &  !   V      x  *   �  J   �  .     c   >  k   �  %        4    G  s  P     �	     �	     �	     �	  &   
  
   3
     >
  H   R
  I   �
  H   �
  I   .  =   x  J   �  E     )   G     q     �     �  3   �  3   �  1        P     d     y     �     �     �  �   �  +   ~  0   �  9   �  1     A   G  :   �    �     �  !   �       z   4  9   �     �       *     q   H  6   �  �   �  q   �  2   �     ,  �  A  *  �     �          '     4  :   B     }     �  K   �  W   �  M   I  Y   �  L   �  ^   >  z   �  w     !   �  #   �     �  I   �  H   0  I   y     �     �     �          %     B  �   V  J      J   k  W   �  J     a   Y  P   �     &                 #         %      3   
   +             !                "          /                       0                        .              -      1         *      '   	                               $   (       ,       )       2               Access token attribute Access token lifetime Authentication authority Base URL (protocol and hostname) of the authentication authority to which tokens management requests will be forwarded Beaker cache selected to store validated tokens Enable JWT direct authentication? Enable JWT proxy authentication? Enable direct login via JWT authentication HS* protocols are using the secret, while RS* protocols are using RSA keys If 'no', SSL certificates will not be verified If selected, this option allows to store credentials in a local cache from which they can be reused If this option is enabled, tokens management requests will be forwarded to another authentication authority JWT access token lifetime, in seconds JWT authentication JWT authentication module "local mode" allows to generate, check and refresh tokens locally.
You can choose to use a simple secret key to encrypt your tokens, or to use a private and public keys pair (which can to be used to share tokens between two applications). JWT authentication module "proxy mode" relies on another authentication authority (which can be another application using this JWT package) to generate, check and refresh tokens. This authority can be used to share access tokens between different applications.
You can cache tokens to reduce the number of requests which will be forwarded to the authentication authority. JWT configuration JWT encoding algorithm JWT private key JWT public key JWT refresh token lifetime, in seconds JWT secret JWT tokens settings Name of the JSON attribute containing access token returned by REST APIs Name of the JSON attribute containing refresh token returned by REST APIs Name of the JSON attribute returned by REST API containing access tokens Name of the JSON attribute returned by REST API containing refresh tokens REST HTTP service used to check validity of an existing token REST HTTP service used to extract claims from provided authorization token REST HTTP service used to get a new access token with a refresh token REST HTTP service used to get a new token Refresh token attribute Refresh token lifetime Selected tokens cache The public key is required when using RS* algorithm The secret key is required when using RS* algorithm This secret is required when using HS* encryption Token claims getter Token getter service Token refresh service Token verify service Use verified tokens cache? Verify SSL? You can use the `openssl` command to generate your keys:

    openssl genpkey -algorithm RSA -out private-key.pem
    openssl rsa -pubout -in private-key.pem -out public-key.pem
 You can't enable both local and proxy modes You must choose a cache to enable tokens caching You must choose an algorithm to enable JWT authentication You must define JWT secret to use HS256 algorithm You must define a private and a public key to use RS256 algorithm You must define authentication authority to use proxy mode Project-Id-Version: PACKAGE 1.0
PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE
Last-Translator: FULL NAME <EMAIL@ADDRESS
Language-Team: LANGUAGE <LL@li.org>
Language: 
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Generated-By: Lingua 3.10.dev0
 Nom du jeton d'accès Durée de vie des jetons d'accès Autorité d'authentification URL de base (protocole et nom d'hôte) de l'autorité d'authentification à laquelle est déléguée la gestion des jetons Cache pré-défini dans lequel seront stockés les jetons Activer le mode "local" ? Activer le mode "proxy" ? Activer la gestion en local des jetons JWT Les protocoles de type HS utilisent le code secret, tandis que les protocoles de types RS utilisent les clés RSA Si 'non', les certificats SSL ne seront pas vérifiés En sélectionnant cette option, les jetons validés seront mis en cache, de façon à limiter les requêtes auprès de l'autorité d'authentification Si cette option est activée, la gestion des jetons JWT est déléguée à une autre autorité d'authentification Durée de vie des jetons d'accès JWT, en secondes Authentification JWT Le mode "local" du module d'authentification JWT permet de générer, vérifier et rafraîchir les jetons JWT localement.
Vous pouvez utiliser un simple secret pour encrypter les jetons, ou utiliser un couple de clés publique et privée (qui peuvent notamment être utilisées pour partager des jetons entre plusieurs applications qui peuvent s'appuyer sur une autorité d'authentification commune). Le mode "proxy" du module d'authentification JWT s'appuie sur une autre autorité d'authentification (qui peut être une autre application utilisant le même package JWT en mode local) pour générer, vérifier et rafraîchir les jetons JWT, via la même API REST. Cette autorité peut par ailleurs être utilisée par différentes applications pour partager des jetons.
Vous pouvez également choisir d'activer un cache dans lequel seront stockés les jetons validés, afin de limiter le nombre de requêtes transmises à l'autorité d'authentification. Configuration JWT Algorithme d'encryptage Clé privée Clé publique Durée de vie des jetons de rafraîchissement, en secondes Code secret Paramétrage des jetons JWT Nom de l'attribut JSON retourné par l'API REST contenant le jeton d'accès Nom de l'attribut JSON retourné par l'API REST contenant le jeton de rafraîchissement Nom de l'attribut JSON retourné par l'API REST contenant les jetons d'accès Nom de l'attribut JSON retourné par l'API REST contenant les jetons de rafraîchissement URL relative du service REST permettant de vérifier la validité d'un jeton URL relative du service REST permettant d'extraire les "réclamations" (claims) des jetons JWT URL relative du service REST permettant de récupérer un nouveau jeton d'accès à partir d'un jeton de rafraîchissement URL relative du service REST permettant de récupérer de nouveaux jetons JWT à partir d'un login et d'un mot de passe Nom du jeton de rafraîchissement Durée de vie des jetons de refresh Cache de jetons Une clé publique est nécessaire pour utiliser un encryptage de type RS* Une clé privée est nécessaire pour utiliser un encryptage de type RS* Ce code secret est nécessaire si vous utilisez un encryptage de type HS* Service de consultation Service d'obtention Service de rafraîchissement Service de vérification Mettre les jetons en cache ? Vérification SSL ? Vous pouvez utiliser la commande `openssl` pour générer vos clés :

         openssl genpkey -algorithm RSA -out private-key.pem
         openssl rsa -pubout -in private-key.pem -out public-key.pem
 Vous ne pouvez pas activer le mode local et le mode proxy en même temps ! Vous devez sélectionner un cache pour activer la mise en cache des jetons Vous devez sélectionner un algorithme d'encryptage pour activer l'authentification JWT Vous devez définir un code secret pour utiliser un encryptage de type HS* Vous devez définir une clé privée et une clé publique pour utiliser un encryptage de type RS* Vous devez indiquer l'autorité d'authentification pour utiliser le mode proxy ! 