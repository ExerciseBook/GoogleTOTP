Uses
	GoogleAuthenticatorCode;
	
Var
	Secret : string;
	Code : string;
	flag : boolean;
Begin
	
	//Generate a secret
	Secret:=GoogleAuthenticatorCode_GenerateASecret();
	writeln('Secret: ',Secret);
	
	//Generate a code
	Code:=GoogleAuthenticatorCode_Gen(Secret);
	writeln('Code: ',Code);
	
	//Verfy
	flag:=GoogleAuthenticatorCode_Verfy(Secret,Code);
	if flag then writeln('Succeed.') else writeln('Failed.');
	flag:=GoogleAuthenticatorCode_Verfy(Secret,'114514');
	if flag then writeln('Succeed.') else writeln('Failed.');
End.