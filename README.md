# Dual-Encryption-Integrative-RSA-AES-Encryption-for-File-Protection
In this project, there are two parts. In the first part, we can see the client-server chat implementation with a GUI where you can send both messages and files. For message transfer, we only use RSA encryption. However, for file transfer, we first encrypt the file with AES encryption and then encrypt the AES key with RSA encryption. This adds an additional layer of security, making it difficult for intruders to crack the file.

In the second part, we have implemented file storage using AES+RSA encryption. Here, we store the file by first encrypting it with AES and then encrypting the AES key with RSA encryption before storing the keys. This makes the file storage more secure such that even if the AES key is compromised, it remains encrypted and needs to be decrypted using RSA.



## Understanding of AES Encryption and Decryption:
ENCRYPTION:
![image](https://github.com/Sivaramasaran2773/Dual-Encryption-Integrative-RSA-AES-Encryption-for-File-Protection/assets/96780921/1707c678-93f3-44a0-ba06-c31da6db9cea)
DECRYPTION:
![image](https://github.com/Sivaramasaran2773/Dual-Encryption-Integrative-RSA-AES-Encryption-for-File-Protection/assets/96780921/ba4ee255-1df4-4ff7-a4ac-872f664fc94e)

## Dual-Encryption: Secure Chat
![image](https://github.com/Sivaramasaran2773/Dual-Encryption-Integrative-RSA-AES-Encryption-for-File-Protection/assets/96780921/435be108-64cb-4c26-9d99-fe64c40850c8)

### Dual-Encryption Secure Chat Flow Chart:
![image](https://github.com/Sivaramasaran2773/Dual-Encryption-Integrative-RSA-AES-Encryption-for-File-Protection/assets/96780921/be643a28-ef1f-4bd9-88f3-c6a5f7d0bfdb)

## Dual-Encryption: Storage
![image](https://github.com/Sivaramasaran2773/Dual-Encryption-Integrative-RSA-AES-Encryption-for-File-Protection/assets/96780921/b7393d84-6e85-4d9f-9be1-49e4b246bbfe)

### Dual-Encryption Storage Flow Chart:
![image](https://github.com/Sivaramasaran2773/Dual-Encryption-Integrative-RSA-AES-Encryption-for-File-Protection/assets/96780921/538666e6-0468-499c-949b-9c3e8948ca89)

## Execution of Programs:
1. Dual-Encryption: Secure Chat

*Make sure that you call the aes1.py in both the server and client files.*
   
In Terminal-1:
<code> python3 server.py </code>

In Terminal-2:
<code> python3 client.py </code>

3. Dual-Encryption: Storage
   
<code> python3 setup.py </code>
