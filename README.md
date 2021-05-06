# RKChat

### Zahteve

Potreben [msgpack](https://pypi.org/project/msgpack/) (`python -m pip install msgpack`) in vsaj `Python 3.8`

---

### Poganjanje streznika:

`python chatServer.py`

Ce streznik javi da **ne najde chatClient** pomeni da je potrebno **zagnati** streznik iz **iste mape** kot kjer je **chatClient**.

### Poganjanje odjemalca:

`python chatClient.py`

Najprej vprasa za naslov streznika in uporabnisko ime. Ce se pritisne enter se vnese vrednost, ki je v `[]`.

Privatni pogovor se izvede z `/w [user] [message...]`
