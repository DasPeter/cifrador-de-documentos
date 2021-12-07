#include <iostream>
#include <fstream>
#include <iomanip>
#include "sodium.h"

void menu();
void generacionClaves();
void cifradoArchivo();
void descifradoArchivo();
void firmaArchivo();
void verificacionFirmaArchivo();

int main()
{
	if (sodium_init() < 0)
	{
		/* panic! the library couldn't be initialized, it is not safe to use */
		return -1;
	}

	while (true)
	{
		menu();
	}
}

void menu()
{
	// Interfaz
	system("cls");
	std::cout << "Software de Proteccion de signedTextos\n\n";
	std::cout << "Elige una herramienta introduciendo el numero:\n";
	std::cout << "1. Generacion y Recuperacion de Claves hacia o desde 1 archivo\n";
	std::cout << "2. Cifrado de Archivos\n";
	std::cout << "3. Descifrado de Archivos\n";
	std::cout << "4. Firma de Archivos\n";
	std::cout << "5. Verificacion de Firma de Archivos\n";
	std::cout << "Otro: Salir del programa\n";

	int option;
	std::cin >> option;

	switch (option)
	{
	case 1:
		system("cls");
		std::cout << "1. Generacion y Recuperacion de Claves hacia o desde 1 archivo\n";
		generacionClaves();
		system("pause");
		break;
	case 2:
		system("cls");
		std::cout << "2. Cifrado de Archivos\n";
		cifradoArchivo();
		system("pause");
		break;
	case 3:
		system("cls");
		std::cout << "3. Descifrado de Archivos\n";
		descifradoArchivo();
		system("pause");
		break;
	case 4:
		system("cls");
		std::cout << "4. Firma de Archivos\n";
		firmaArchivo();
		system("pause");
		break;
	case 5:
		system("cls");
		std::cout << "5. Verificacion de Firma de Archivos\n";
		verificacionFirmaArchivo();
		system("pause");
		break;
	default:
		exit(1); // End program
	}
}

void generacionClaves()
{
	// Arrays to store keys
	unsigned char publicKey[crypto_sign_PUBLICKEYBYTES];
	unsigned char secretKey[crypto_sign_SECRETKEYBYTES];

	// Generate key pair
	crypto_sign_keypair(publicKey, secretKey);

	// Create private key file
	FILE *publicKeyFile;
	fopen_s(&publicKeyFile, "publickey.txt", "wb");
	fwrite(publicKey, 1, crypto_sign_PUBLICKEYBYTES, publicKeyFile);
	fclose(publicKeyFile);
	std::cout << "\nPublic key generada: 'publickey.txt'\n\n";

	// Create private key file
	FILE *secretKeyFile;
	fopen_s(&secretKeyFile, "secretkey.txt", "wb");
	fwrite(secretKey, 1, crypto_sign_SECRETKEYBYTES, secretKeyFile);
	fclose(secretKeyFile);
	std::cout << "Secret key generada: 'secretkey.txt'\n\n";
}

void cifradoArchivo()
{
	// Open original file
	FILE *originalFile;
	char originalFileName[100];

	// Get and verify file name
	std::cout << "\nIngrese un nombre de archivo para encriptar:\n";
	std::cin >> originalFileName;
	fopen_s(&originalFile, originalFileName, "rb");
	if (originalFile == NULL)
	{
		std::cout << "\nNombre de archivo a encriptar no encontrado\n\n";
		return;
	}

	// Get original file size
	fseek(originalFile, 0, SEEK_END);
	long fileSize = ftell(originalFile);
	fseek(originalFile, 0, SEEK_SET);

	// Create arrays to store original and encripted file contents
	unsigned char *originalText = new unsigned char[fileSize];
	unsigned char *encriptedText = new unsigned char[fileSize];

	// Read original file
	fread(originalText, 1, fileSize, originalFile);
	fclose(originalFile);

	// Generate nonce and key
	unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
	unsigned char key[crypto_stream_chacha20_KEYBYTES];
	randombytes_buf(nonce, sizeof nonce); // Generate new nonce
	crypto_secretbox_keygen(key);         // Generate new key

	// Execute encryption
	int toCipher = crypto_stream_chacha20_xor(encriptedText, originalText, fileSize, nonce, key);

	// Generate and save encripted text
	FILE *encriptedFile;
	fopen_s(&encriptedFile, "encripted.txt", "wb");
	fwrite(encriptedText, 1, fileSize, encriptedFile);
	std::cout << "\nSe han generado un archivo con el texto encriptado: 'encripted.txt'\n";
	fclose(encriptedFile);

	// Generate nonce file
	FILE *nonceFile;
	fopen_s(&nonceFile, "nonce.txt", "wb");
	fwrite(nonce, 1, crypto_stream_chacha20_NONCEBYTES, nonceFile);
	fclose(nonceFile);
	std::cout << "\nArchivo de nonce generado: 'nonce.txt'\n";

	// Generate key file
	FILE *keyFile;
	fopen_s(&keyFile, "key.txt", "wb");
	fwrite(key, 1, crypto_stream_chacha20_KEYBYTES, keyFile);
	fclose(keyFile);
	std::cout << "\nArchivo de key generado: 'key.txt'\n\n";
}

void descifradoArchivo()
{
	// Declare variables to open open files
	FILE *encriptedFile;
	FILE *nonceFile;
	FILE *keyFile;
	FILE *decriptedFile;
	char encriptedFileName[100];
	char nonceFileName[100];
	char keyFileName[100];

	// Get and validate file names
	std::cout << "\nIngrese un nombre de archivo encriptado:\n";
	std::cin >> encriptedFileName;
	fopen_s(&encriptedFile, encriptedFileName, "rb");
	if (encriptedFile == NULL)
	{
		std::cout << "\nNombre de archivo encriptado no encontrado\n\n";
		return;
	}
	std::cout << "\nIngrese un nombre de archivo nonce:\n";
	std::cin >> nonceFileName;
	fopen_s(&nonceFile, nonceFileName, "rb");
	if (nonceFile == NULL)
	{
		std::cout << "\nNombre de archivo nonce no encontrado\n\n";
		fclose(encriptedFile);
		return;
	}
	std::cout << "\nIngrese un nombre de archivo key:\n";
	std::cin >> keyFileName;
	fopen_s(&keyFile, keyFileName, "rb");
	if (keyFile == NULL)
	{
		std::cout << "\nNombre de archivo key no encontrado\n\n";
		fclose(encriptedFile);
		fclose(nonceFile);
		return;
	}

	// Get encripted file length
	fseek(encriptedFile, 0, SEEK_END);
	long fileSize = ftell(encriptedFile);

	// Variables to store encripted ande decripted text
	unsigned char *encriptedText = new unsigned char[fileSize];
	unsigned char *decriptedText = new unsigned char[fileSize];

	// Read encripted file
	fseek(encriptedFile, 0, SEEK_SET);
	fread(encriptedText, 1, fileSize, encriptedFile);
	fclose(encriptedFile);

	// Read nonce
	fseek(nonceFile, 0, SEEK_END);
	long nonceSize = ftell(nonceFile);
	unsigned char *nonce = new unsigned char[crypto_stream_chacha20_NONCEBYTES];
	fseek(nonceFile, 0, SEEK_SET);
	fread(nonce, 1, nonceSize, nonceFile);
	fclose(nonceFile);

	// Read key
	fseek(keyFile, 0, SEEK_END);
	long keySize = ftell(keyFile);
	unsigned char *key = new unsigned char[crypto_stream_chacha20_KEYBYTES];
	fseek(keyFile, 0, SEEK_SET);
	fread(key, 1, keySize, keyFile);
	fclose(keyFile);

	// Execute decripction
	int toDecrypt = crypto_stream_chacha20_xor(decriptedText, encriptedText, fileSize, nonce, key);

	// Save decripted message
	fopen_s(&decriptedFile, "decripted.txt", "wb");
	fwrite(decriptedText, 1, fileSize, decriptedFile);
	fclose(decriptedFile);
	std::cout << "\nArchivo descifrado guardado correctamente\n\n";
}

void firmaArchivo()
{
	// Declare variables to open open files
	FILE *originalFile;
	FILE *secretKeyFile;
	char originalFileName[100];
	char secretKeyFileName[100];

	// Open and validate file names
	std::cout << "\nIngrese un nombre de archivo a firmar:\n";
	std::cin >> originalFileName;
	fopen_s(&originalFile, originalFileName, "rb");
	if (originalFile == NULL)
	{
		std::cout << "\nNombre de archivo a firmar no encontrado\n\n";
		return;
	}
	std::cout << "\nIngrese un nombre de archivo de llave privada:\n";
	std::cin >> secretKeyFileName;
	fopen_s(&secretKeyFile, secretKeyFileName, "rb");
	if (secretKeyFile == NULL)
	{
		std::cout << "\nNombre de archivo de llave privada no encontrado\n\n";
		fclose(originalFile);
		return;
	}

	// Read original file
	// Get length of original file
	fseek(originalFile, 0, SEEK_END);
	long fileSize = ftell(originalFile);
	fseek(originalFile, 0, SEEK_SET);

	// Create array to store original file contents
	unsigned char *originalText = new unsigned char[fileSize];

	// Read and close original file
	fread(originalText, 1, fileSize, originalFile);
	fclose(originalFile);

	// Read private key file
	fseek(secretKeyFile, 0, SEEK_END);
	long secretKeySize = ftell(secretKeyFile);

	// Create array to store private key file contents
	unsigned char *publicKey = new unsigned char[secretKeySize];

	// Read and close private key file
	fseek(secretKeyFile, 0, SEEK_SET);
	fread(publicKey, 1, secretKeySize, secretKeyFile);
	fclose(secretKeyFile);

	// Create signed text arrays to store signed content
	unsigned char *signedText = new unsigned char[crypto_sign_BYTES + fileSize];
	unsigned long long signedSize;

	// Sign file
	crypto_sign(signedText, &signedSize, originalText, fileSize, publicKey);

	// Create and save signed file
	FILE *signedFile;
	fopen_s(&signedFile, "signed.txt", "wb");
	fwrite(signedText, 1, signedSize, signedFile);
	fclose(signedFile);
	std::cout << "\nArchivo firmado y guardado correctamente\n\n";
}

void verificacionFirmaArchivo()
{
	// Declare variables to open open files
	FILE *signedFile;
	FILE *publicKeyFile;
	char signedFileName[300];
	char publicKeyFileName[300];

	// Open and validate file names
	std::cout << "\nIngrese un nombre de archivo a verificar:\n";
	std::cin >> signedFileName;
	fopen_s(&signedFile, signedFileName, "rb");
	if (signedFile == NULL)
	{
		std::cout << "\nNombre de archivo a verificar no encontrado\n\n";
		return;
	}
	std::cout << "\nIngrese un nombre de archivo de llave publica:\n";
	std::cin >> publicKeyFileName;
	fopen_s(&publicKeyFile, publicKeyFileName, "rb");
	if (publicKeyFile == NULL)
	{
		std::cout << "\nNombre de archivo de llave publica no encontrado\n\n";
		fclose(signedFile);
		return;
	}

	// Read signed file
	// Get length of signed file
	fseek(signedFile, 0, SEEK_END);
	long fileSize = ftell(signedFile);
	fseek(signedFile, 0, SEEK_SET);

	// Create array to store signed file contents
	unsigned char *signedText = new unsigned char[fileSize];

	// Read and close signed file
	fread(signedText, 1, fileSize, signedFile);
	fclose(signedFile);

	// Read public key file
	// Get length of public key file
	fseek(publicKeyFile, 0, SEEK_END);
	long publicKeySize = ftell(publicKeyFile);
	fseek(publicKeyFile, 0, SEEK_SET);

	// Create array to store public key file contents
	unsigned char *publicKeyText = new unsigned char[publicKeySize];

	// Read and close public key file
	fread(publicKeyText, 1, publicKeySize, publicKeyFile);
	fclose(publicKeyFile);

	// Validate signature
	// Create array to store validated file contents
	unsigned char *signatureValidatedText = new unsigned char[fileSize - crypto_sign_BYTES];
	unsigned long long signatureValidatedSize;

	if (crypto_sign_open(signatureValidatedText, &signatureValidatedSize, signedText, fileSize, publicKeyText) != 0)
	{
		std::cout << "\nFirma no valida\n";
	}
	else
	{
		std::cout << "\nFirma valida\n";

		// Create and save unsigned file
		FILE *signatureValidatedFile;
		fopen_s(&signatureValidatedFile, "unsigned.txt", "wb");
		fwrite(signatureValidatedText, 1, signatureValidatedSize, signatureValidatedFile);
		fclose(signatureValidatedFile);
		std::cout << "\nArchivo sin firma guardado correctamente\n\n";
	}
}
