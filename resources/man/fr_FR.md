% RootAsRole(8) RootAsRole 3.3.4 | Manuel de l'administrateur système
% Eddie Billoir <lechatp@outlook.fr>
% Août 2025

# NAME
RootAsRole - Une alternative pour les commandes sudo/su respectant le principe du moindre privilège et une gestion de la mémoire plus sécurisée.

# SYNOPSIS
- **dosr** [__OPTIONS__] [__COMMAND__]...
- **chsr** [__ARGUMENTS__]
    Les arguments suivent une grammaire disponible dans le code source à l'adresse <https://github.com/LeChatP/RootAsRole/tree/main/src/chsr/cli/cli.pest>

# DESCRIPTION
**RootAsRole** est un outil pour les administrateurs qui fournit un système structuré de contrôle d'accès basé sur les rôles (RBAC) pour déléguer les tâches administratives et les droits d'accès. Il prend notamment en charge les __Linux capabilities(7)__ pour minimiser les privilèges des utilisateurs.

Le modèle de Roles Based Access Control (RBAC) est basé sur des ensembles de permissions assignées à des utilisateurs ou des groupes. Pour RootAsRole, un rôle est un ensemble de tâches administratives assignées à des utilisateurs. Les tâches sont des commandes avec des droits à utiliser. Les droits peuvent être un changement d'utilisateur, un changement de groupe ou/et des Linux capabilities.

La commande **dosr** permet d'exécuter des commandes en utilisant un rôle. Il prends en paramètre obligatoire une commande à exécuter. Il est également possible de spécifier un rôle et une tâche à sélectionner.

Il existe des cas où deux tâches correspondent à la commande d'un utilisateur. Dans ce cas, dosr va sélectionner la tâche la plus précise et la moins privilégiée. La notion de précision est basée sur la précision de la politique RootAsRole comparée à l'occurence de la commande utilisateur. Plus le profil utilisateur et correspond à la politique, plus le niveau de précision est élevé. Il en est de même pour la précision de la commande de l'utilisateur vis-à-vis de sa spécification dans la politique. Pareillement, moins les droits sont élevés pour une tâche, plus la tâche sera prioritaire par rapport à une autre tâche. Le cas de la tâche moins privilégié n'est qu'uniquement si les tâches sont déjà avec le même niveau de précision. Malgré cette sélection intelligente, il reste des cas de confusion, ceux-ci renvoient un message d'erreur.

Exemple d'un cas de confusion : Deux rôles sont assignés de la même manière à un utilisateur, parmi ces rôles, deux tâches sont totalement équivalentes mais les variables d'environment sont différents. Dans ce cas, dosr affiche le message d'erreur "Permission denied" et fais un message warning dans les logs.

Il est possible de changer le prompt de l'utilisateur en utilisant l'option **-p**. Il est également possible de voir les droits de l'exécuteur en utilisant l'option **-i**. Les informations affichées sont très limitées.

La commande **chsr** sert à configurer RootAsRole et sa politique de contrôle d'accès. Elle permet de configurer les rôles, les tâches et les permissions. La configuration est stockée dans le fichier **/etc/security/rootasrole.json**. Si le système de fichier le permet, le fichier est rendu immuable, il faut alors le privilège CAP_LINUX_IMMUTABLE pour utiliser **chsr**. Pour cela, la politique par défaut de RootAsRole donne la permission à l'installateur d'utiliser **chsr** avec les privilèges nécessaires.

Il est possible de configurer le mode de stockage de la politique de contrôle d'accès. Par défaut, RootAsRole utilise un fichier JSON. Il est possible de changer le mode de stockage en modifiant manuellement le fichier **/etc/security/rootasrole.json**.

Concernant l'authentification, RootAsRole utilise PAM. Il est possible de configurer le fichier **/etc/pam.d/dosr** pour changer le comportement de l'authentification.

Le coeur de RootAsRole implémente RBAC-0, une version simplifiée de RBAC. Par défaut il ajoute des fonctionnalités sous forme de plugins pour implémenter certaines fonctionnalités de RBAC-1. RBAC-0 implémente simplement les rôles, les tâches et les permissions. Les plugins ajoutent la hiérarchie de rôles et séparation des devoirs. Les plugins sont uniquement implémentable directement dans le projet. Il y a également un autre plugin qui permet de tester la somme de contrôle des fichiers exécutés.

# OPTIONS

**\-r, --role** &lt;ROLE&gt;
  Sélectionner un rôle spécifique.

**\-t, --task** &lt;TASK&gt;
  Sélectionner une tâche spécifique dans un rôle (--role requis)

**\-u USER, --user** &lt;USER&gt;
  Exécuter la commande en tant qu'un utilisateur spécifique (sert de filtre pour sélectionner une tâche)

**\-g GROUP(,GROUP...) , --group** &lt;GROUP(,GROUP...)&gt;
  Exécuter la commande en tant que groupe(s) spécifique(s) (sert de filtre pour sélectionner une tâche)

**\-E, --preserve-env**  
  Préserver les variables d'environnement du processus courant si autorisé par une tâche correspondante.

**\-p, --prompt** &lt;PROMPT&gt; 
  Prompt à afficher lors de l'authentification.

**\-K**  
  Supprimer le fichier de timestamp. (Cela oblige de s'authentifier à nouveau avant d'exécuter une commande)

**\-i, --info**  
  Afficher le contexte d'exécution d'une commande si autorisé par une tâche correspondante.

**\-h, --help**  
  Afficher l'aide (voir plus avec '--help')

**\-v, --version**  
  Afficher les informations de version

# EXEMPLES

- **dosr reboot**  
  Exécute la commande reboot (si la politique le permet).

- **dosr -r dac chmod 644 /etc/foo/bar**
  Exécute la commande chmod 644 /etc/foo/bar avec le rôle dac (si la politique a un rôle dac et une tâche qui permet la commande chmod).

# HISTORIQUE

Vous pouvez trouver l'historique de RootAsRole sur le site web <https://lechatp.github.io/RootAsRole/HISTORY.html>.

# RISQUES DE SÉCURITÉ

RootAsRole est un outil de sécurité qui peut donner le contrôle complet du système à un utilisateur. Un administrateur peut écrire une politique de contrôle d'accès qui donne des droits trop élevés à un utilisateur. Une expression régulière perl (pcre2) est une librairie très complexe et peut accepter des caractères spéciaux inattendus.

Il peut être difficile de déterminer les droits nécessaire pour une commande. Pour cela, il est possible d'utiliser l'outil "capable" disponible sur <https://github.com/LeChatP/RootAsRole-capable/> pour déterminer les capabilities nécessaires pour une commande. Cependant, il est également possible que cette commande donne trop de capabilities. Il est donc recommandé de vérifier si les capabilities sont bien nécessaires car dans la plupart des cas, les capabilities ne sont pas nécessaires. Il est fortement déconseillé d'utiliser cet outil en production.

# SUPPORT

Pour obtenir de l'aide, veuillez consulter <https://github.com/LeChatP/RootAsRole/discussions> ou <https://github.com/LeChatP/RootAsRole/issues> si vous avez trouvé un bogue.

# CLAUSE DE NON-RESPONSABILITÉ

Ce programme est fourni « en l'état », sans aucune garantie, dans la limite permise par la loi. Les auteurs déclinent toute responsabilité quant à la qualité ou l'adéquation du programme à un usage particulier. Vous utilisez ce programme à vos propres risques. En cas de problème, vous êtes responsable des réparations ou corrections nécessaires. Pour plus de détails, veuillez consulter la licence GNU LGPL version 3 ou ultérieure <https://www.gnu.org/licenses/lgpl-3.0.html>.

# AUTEUR
Ce manuel a été écrit par Eddie BILLOIR <lechatp@outlook.fr>

# LICENCE
License LGPLv3+: GNU LGPL version 3 or later <https://www.gnu.org/licenses/lgpl-3.0.html>.

# VOIR AUSSI
Linux capabilities(7), sudo(8), su(1)
