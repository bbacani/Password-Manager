#!/bin/bash

# Rjesenje je pisano u python-u, potreban je python 3.8 prevoditelj i biblioteka pycryptodome.

# Inicijaliziramo bazu na sljedeci nacin:
python3 password_manager.py init masterPassword

# Dodajemo zaporku na sljedeci nacin:
python3 password_manager.py put masterPassword www.fer.hr zaporka

# Dohvacamo zaporku na sljedeci nacin:
python3 password_manager.py get masterPassword www.fer.hr
