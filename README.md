# encrypt_syscall

Syntax:
	./xcipher -p "passkey" [-e -d] infile outfile

Description:
	xcipher takes an input file and [encypts decrypts] it with SHA1 hash of passkey passed by user.

Options:
	-h:	Display a help message and exit.
	
	-e: 	encrypts the input file.
	
	-d:	decrypts the input file.
	
	-p:	next argument after this option is a passkey of at least 6 characters long used to encrypt or decrypt input file.

Example:

	./xcipher -h
	
	./xcipher -p "This is my Key" -e input.txt output.txt
