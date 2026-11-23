SEED SQL Injection Attack Lab - CyberRangeCZ
=============================================

Site vulnerable
---------------
Ouvrez http://www.seed-server.com dans le navigateur de la VM.

Base MySQL (lecture seule)
-------------------------
mysql -h 127.0.0.1 -u student_ro -pdees sqllab_users

Validations
-----------
sqllab check 1
sqllab check 2
sqllab check 3
sqllab check 4

Defense par requete preparee
----------------------------
Modifiez uniquement :
  ~/lab/defense/unsafe.php

Le serveur voit les changements immediatement ; aucun rebuild Docker n'est
necessaire. La page de test est http://www.seed-server.com/defense/

Remise a zero
-------------
sudo reset-sqllab

Cette commande restaure la base initiale et le fichier de defense. Elle efface
donc la progression locale des taches 3 et 4.

Toutes les manipulations doivent rester dans cette sandbox pedagogique.
