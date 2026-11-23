# SEED Lab « SQL Injection Attack » pour CyberRangeCZ

Formation linéaire pour [CyberRangeCZ](https://docs.platform.cyberrange.cz/) adaptée du [SEED Lab *SQL Injection Attack*](https://seedsecuritylabs.org/Labs_20.04/Web/Web_SQL_Injection/) de Wenliang Du.

Le laboratoire place l'étudiant dans une application de gestion d'employés volontairement vulnérable. Il commence par interroger la base, contourne ensuite une authentification avec une injection SQL, exploite une requête `UPDATE`, puis corrige la vulnérabilité avec une requête préparée.

> Ce dépôt est exclusivement destiné à un environnement pédagogique isolé. N'essayez jamais ces techniques contre un système sans autorisation explicite.

## Parcours et barème

| Niveau | Activité | Validation | Points |
|---:|---|---|---:|
| 0 | Introduction, règles et barème | Information | — |
| 1 | Accès à la sandbox | Passkey `start` | — |
| 2 | Tâche 1 : requêtes SQL de base | `sqllab check 1` | 20 |
| 3 | Tâche 2 : injection sur `SELECT` depuis le Web et `curl` | `sqllab check 2` | 60 |
| 4 | Tâche 3 : injection sur `UPDATE` | `sqllab check 3` | 80 |
| 5 | Tâche 4 : défense par requête préparée | `sqllab check 4` | 40 |
| 6 | Compte rendu | Information | — |

Le total est de **200 points**, soit une note sur 20 égale au score divisé par 10. Les quatre flags sont différents dans chaque sandbox. Les indices retirent des points et l'affichage d'une solution annule les points du niveau concerné.

## Architecture

La topologie CyberRangeCZ contient une VM `seed` et un routeur vers le WAN. Les services du laboratoire fonctionnent dans deux conteneurs internes à la VM :

```text
Navigateur et terminal de la VM seed
            │
            ├── http://www.seed-server.com
            │         └── application PHP volontairement vulnérable
            │
            └── MySQL local
                      └── base sqllab_users
```

L'étudiant se connecte à la VM avec `seed` / `dees`. Ce compte :

- ne possède ni droit d'administration général ni accès au moteur Docker ;
- peut interroger MySQL avec `student_ro` / `dees`, un compte limité à `SELECT` ;
- peut modifier `~/lab/defense/unsafe.php` pour la tâche 4 ;
- peut uniquement lancer la commande administrative bornée `sudo reset-sqllab` afin de rétablir les données pédagogiques après une erreur.

Les conteneurs sont construits et démarrés par le provisioning. L'étudiant n'a pas besoin de `docker exec`, de `docker compose` ni d'un shell root.

## Flags et validation

`variables.yml` déclare quatre variables APG : `flag_task1`, `flag_task2`, `flag_task3` et `flag_task4`. CyberRangeCZ produit une valeur différente pour chaque sandbox et l'utilise comme réponse attendue dans `training.json`.

Le binaire `/usr/local/bin/sqllab` vérifie l'état réel du laboratoire avant d'afficher le flag correspondant :

- tâche 1 : réponses tirées de la fiche d'Alice ;
- tâche 2 : contournement de l'authentification avec une charge utile valide ;
- tâche 3 : modifications d'Alice et Boby, puis nouveau mot de passe de Boby ;
- tâche 4 : login légitime conservé et injection bloquée par la correction.

Le validateur appartient à `root`, est exécutable mais illisible par l'étudiant, et ne place aucun flag dans le code PHP ni dans la base de données. Le compte `seed` ne reçoit pas l'accès Docker, qui équivaudrait à un accès root et permettrait de contourner les contrôles.

## Structure du dépôt

```text
topology.yml                      topologie CyberRangeCZ
variables.yml                     quatre flags APG par sandbox
training.json                     scénario, niveaux, indices et solutions
game_design.md                    conception pédagogique et validations
provisioning/
  playbook.yml                    orchestration Ansible
  requirements.yml                rôles CyberRangeCZ externes
  host_vars/seed.yml              interpréteur Python de la VM
  roles/
    hosts/                        dépendances du laboratoire
    sql-injection-lab/
      defaults/                   paramètres du rôle
      files/Labsetup/             application PHP et base MySQL SEED
      files/lab/                  fichiers remis à l'étudiant
      tasks/                      déploiement, tests et durcissement
      handlers/                   redémarrages contrôlés
```

Les données MySQL, sels, flags temporaires, secrets générés et binaires de validation ne doivent jamais être ajoutés au dépôt ; ils sont couverts par `.gitignore`.

## Utilisation par l'étudiant

Après connexion à la VM :

```bash
cat ~/lab/README.txt
curl -I http://www.seed-server.com/
mysql -h 127.0.0.1 -u student_ro -pdees sqllab_users
```

Le navigateur de la VM ouvre `http://www.seed-server.com`. Les consignes détaillées et les réponses attendues sont présentées directement dans la formation CyberRangeCZ.

En cas de modification involontaire empêchant de continuer :

```bash
sudo reset-sqllab
```

Cette règle sudo n'autorise que le programme de réinitialisation prévu ; elle ne donne pas de shell administrateur. La réinitialisation remet les profils et le fichier de défense dans leur état initial, et efface la progression locale des tâches 3 et 4.

## Déploiement CyberRangeCZ

1. Vérifier que les images et utilisateurs de gestion définis dans `topology.yml` existent sur l'instance de l'établissement.
2. Pousser le dépôt vers un dépôt Git accessible par CyberRangeCZ, sur la branche `main`.
3. Créer une *Sandbox Definition* pointant vers l'URL Git et la révision `main`.
4. Créer un pool, puis allouer les sandboxes.
5. Importer `training.json` dans *Training Agenda > Training Definition*.
6. Créer l'instance de formation, lui associer le pool et tester l'intégralité du parcours avant de distribuer le jeton d'accès.

Le déploiement cloud dépend des images, flavors, accès réseau et versions Docker disponibles dans l'instance CyberRangeCZ cible. **Ce dépôt ne prétend pas avoir déjà été validé sur cette instance tant qu'un test complet de sandbox n'a pas été réalisé.**

## Vérifications avant publication

Au minimum :

- valider la syntaxe de `training.json`, des fichiers YAML et du playbook Ansible ;
- exécuter `docker compose config`, construire les images et attendre les healthchecks ;
- confirmer que `student_ro` peut lire mais ne peut ni modifier la base ni créer de table ;
- vérifier que l'injection `SELECT` et les trois injections `UPDATE` fonctionnent dans l'état initial ;
- vérifier que la correction par requête préparée accepte un login légitime et refuse la même injection ;
- exécuter l'auto-test du checker et contrôler ses permissions ;
- confirmer avec `sudo -l -U seed` que seule la réinitialisation bornée est permise et que `seed` n'appartient pas au groupe `docker`.

## Licence et attribution

- Le contenu pédagogique adapté du SEED Lab, ainsi que les éléments SEED réutilisés, relèvent de la licence **CC BY-NC-SA 4.0**. L'avis de copyright original doit être conservé.
- Le code original écrit pour ce dépôt est sous licence **MIT**, sauf mention contraire dans le fichier concerné.
- La licence MIT ne remplace ni ne modifie la licence du contenu SEED.

Voir [ATTRIBUTION.txt](ATTRIBUTION.txt), [LICENSE](LICENSE) et le dossier [LICENSES](LICENSES/).

