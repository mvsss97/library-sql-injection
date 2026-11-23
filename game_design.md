# Conception pédagogique — SEED SQL Injection

## Intention

Le laboratoire montre comment une application Web transforme une donnée non contrôlée en code SQL, mesure les conséquences sur la confidentialité et l'intégrité, puis fait corriger la cause avec des requêtes préparées. Il adapte fidèlement les quatre tâches du *SEED Labs – SQL Injection Attack Lab* à un parcours linéaire CyberRangeCZ en français.

Les attaques sont limitées à l'application vulnérable de la sandbox. Le niveau d'introduction rappelle explicitement le cadre légal et éthique.

## Principes de conception

- **Progression complète** : lire avec `SELECT`, contourner une authentification, modifier avec `UPDATE`, puis séparer le code et les données.
- **Expérience réelle** : le validateur contrôle l'application ou la base au moment de la réponse ; il ne se contente pas d'une question théorique.
- **Flags propres à la sandbox** : quatre variables APG alimentent quatre niveaux à réponses variantes.
- **Compte rendu complémentaire** : les captures, requêtes, observations et explications restent évaluées humainement.
- **Privilèges minimaux** : `seed` n'a ni sudo général ni Docker. Le seul droit administratif autorisé est `sudo reset-sqllab`, limité à une remise à zéro déterministe.
- **Récupération pédagogique** : une mauvaise injection ne doit pas obliger à recréer la sandbox.
- **Fidélité avec adaptation** : les noms Alice, Boby et Admin, la table `credential`, les injections `SELECT`/`UPDATE` et la défense par prepared statement sont conservés ; l'accès root au conteneur du document original est remplacé par des interfaces bornées.

## Barème

| Tâche | Compétence principale | Points |
|---|---|---:|
| 1 | Interroger une table et filtrer une ligne | 20 |
| 2 | Exploiter une injection sur `SELECT` depuis deux clients | 60 |
| 3 | Exploiter une injection sur `UPDATE` et raisonner sur SHA-1 | 80 |
| 4 | Corriger avec une requête préparée | 40 |
| **Total** |  | **200** |

La note sur 20 vaut `score / 10`. Chaque indice a une pénalité annoncée. Une solution affichée est pénalisée par CyberRangeCZ et vaut zéro pour le niveau.

## Niveau 0 — Introduction

Le niveau décrit le scénario, le barème, les règles, les quatre flags et l'obligation de produire un compte rendu. Il explique que l'environnement est volontairement vulnérable et strictement isolé.

## Niveau 1 — Accès

Objectifs :

- ouvrir la VM `seed` ;
- se connecter avec `seed` / `dees` ;
- ouvrir `http://www.seed-server.com` ;
- vérifier la base avec le compte `student_ro` en lecture seule ;
- comprendre le rôle borné de `sudo reset-sqllab`.

La passkey `start` confirme seulement que l'environnement est accessible.

## Tâche 1 — Se familiariser avec SQL

### Objectif

Utiliser `USE`, `SHOW TABLES`, `DESCRIBE` et `SELECT ... WHERE ...` pour comprendre la base `sqllab_users` et extraire la ligne d'Alice.

### Activité

L'étudiant se connecte à MySQL avec `student_ro`, inspecte `credential` et retrouve l'EID, le salaire et le SSN d'Alice. Le compte est limité à `SELECT` : il autorise l'apprentissage des requêtes sans offrir une voie de contournement des tâches d'écriture.

### Validation

`sqllab check 1` demande les valeurs observées, les compare à l'état de référence et révèle `flag_task1`.

### Preuves attendues dans le rapport

- commande de connexion ;
- requête SQL filtrée sur Alice ;
- résultat et explication de la clause `WHERE`.

## Tâche 2 — Injection sur `SELECT`

### Objectif

Comprendre comment l'entrée `username` est concaténée dans une requête d'authentification et comment un commentaire SQL peut neutraliser la vérification du mot de passe.

### Activités

1. Contourner le formulaire dans le navigateur et obtenir la vue Admin.
2. Refaire l'attaque avec `curl`, en encodant correctement apostrophe, espace et caractère de commentaire dans l'URL.
3. Tenter d'ajouter une seconde instruction et expliquer pourquoi elle n'est pas exécutée : l'API `mysqli::query()` traite une seule instruction, contrairement à une interface explicitement multi-requêtes telle que `multi_query()`.

### Validation

`sqllab check 2` vérifie une charge utile URL-encodée contre l'application active et révèle `flag_task2` lorsqu'elle atteint bien la vue administrateur.

### Preuves attendues

- capture de la vue Admin depuis le navigateur ;
- commande `curl` et réponse pertinente ;
- reconstitution de la requête finale ;
- résultat de la tentative de requêtes empilées et explication.

## Tâche 3 — Injection sur `UPDATE`

### Objectif

Montrer qu'une injection affectant une écriture compromet l'intégrité de données d'autres utilisateurs.

### Activités

Après une connexion légitime comme Alice, l'étudiant exploite la page *Edit Profile* pour :

1. augmenter son propre salaire ;
2. fixer le salaire de Boby à `1` ;
3. remplacer le hash du mot de passe de Boby par le SHA-1 d'un secret choisi ;
4. prouver la modification en se connectant comme Boby avec ce secret.

Les charges utiles doivent fermer la valeur courante, ajouter l'affectation voulue, cibler explicitement la bonne ligne avec `WHERE`, puis commenter la fin de la requête d'origine.

### Validation

`sqllab check 3` lit l'état courant, vérifie les deux salaires, compare le SHA-1 du mot de passe fourni par l'étudiant et confirme la possibilité d'une authentification Boby avant de révéler `flag_task3`.

### Récupération

`sudo reset-sqllab` rétablit les profils initiaux si une charge utile modifie trop de lignes. Le reset ne donne aucun shell root et remet aussi le fichier de défense dans son état vulnérable.

## Tâche 4 — Requête préparée

### Objectif

Corriger la cause de l'injection en séparant le plan SQL des valeurs fournies par l'utilisateur.

### Activité

L'étudiant modifie `~/lab/defense/unsafe.php`. Ce fichier est monté dans l'application ; aucune commande Docker ni reconstruction d'image n'est nécessaire. La correction doit :

- appeler `prepare()` avec deux paramètres `?` ;
- lier le nom et le hash avec `bind_param("ss", ...)` ;
- exécuter la requête ;
- retourner les mêmes données pour des identifiants légitimes ;
- refuser la charge utile précédemment efficace.

### Validation

`sqllab check 4` combine contrôle fonctionnel et inspection ciblée du source. Il révèle `flag_task4` seulement si un login normal réussit et si l'injection échoue.

## Compte rendu

Le rendu doit contenir, pour chaque tâche :

- les commandes et charges utiles importantes ;
- des captures lisibles et contextualisées ;
- la requête SQL résultante ;
- les observations et leur explication ;
- pour la tâche 4, le code corrigé et une comparaison avant/après.

Une suite de captures ou de code sans explication ne suffit pas.

## Modèle de menace et anti-contournement

Le laboratoire protège les flags et la valeur pédagogique sans prétendre résister à un administrateur de la plateforme :

- le compte étudiant n'appartient pas aux groupes `sudo`, `docker`, `lxd`, `adm`, `disk` ou équivalents ;
- `student_ro` n'a que `SELECT` ;
- les comptes applicatifs MySQL sont limités à leur origine réseau et à leurs privilèges nécessaires ;
- les flags ne sont stockés ni dans les pages PHP ni dans les lignes de la base ;
- le checker est root:root, mode `0711`, avec auto-test root ne retournant que des empreintes ;
- les fichiers temporaires contenant des variables APG sont root `0600`, masqués dans les logs Ansible et supprimés après compilation ;
- la zone de défense utilise un compte SQL en lecture seule, afin qu'un fichier PHP modifié ne devienne pas une voie d'écriture arbitraire.

## Critères de recette

Avant diffusion, un enseignant doit effectuer le parcours entier dans une sandbox neuve, puis après reset :

1. accès Web et MySQL ;
2. refus d'un `UPDATE` direct par `student_ro` ;
3. réussite de l'injection `SELECT` depuis le navigateur et `curl` ;
4. échec contrôlé des requêtes empilées ;
5. réussite des trois modifications `UPDATE` uniquement via l'application ;
6. connexion Boby avec le nouveau mot de passe ;
7. réussite d'un login normal après correction et échec de l'injection ;
8. validation des quatre flags propres à la sandbox ;
9. absence de sudo général et d'accès Docker pour `seed`.

Tant que cette recette n'a pas été exécutée sur l'instance cible, la compatibilité cloud reste à confirmer.
