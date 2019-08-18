{
Copyright <2019> <Eric_Lian>

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software 
without restriction, including without limitation the rights to use, copy, modify, 
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
permit persons to whom the Software is furnished to do so, subject to the following 
conditions:

The above copyright notice and this permission notice shall be included in all copies 
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.
}

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