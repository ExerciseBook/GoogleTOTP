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

{$mode delphi}

unit GoogleAuthenticatorCode;

interface
Uses
	dateutils,sysutils,
	HMAC;

Function GoogleAuthenticatorCode_Gen(secret:string):string;overload;
Function GoogleAuthenticatorCode_Verfy(const secret,submit:string):boolean;
Function GoogleAuthenticatorCode_GenerateASecret:string;

implementation
Var
	Base32Alphabet :array[0..31] of char;

Type
	Base32Exception_InvalidLetter = Class(Exception);

Function Base32_Encode(a:string):string;
Var
	i : longint;
	back : string;
	
	remain : longint;
	scan : longint;
Begin
	back:='';
	scan:=0;
	remain:=0;
	for i:=1 to length(a) do begin
		remain:=remain*256+longint(a[i]);
		inc(scan);
		
		case scan mod 5 of
			0: begin
				back:=back+Base32Alphabet[remain shr 5]; remain:=remain and $1F;
				back:=back+Base32Alphabet[remain]; remain:=0;
			end;
			1: begin back:=back+Base32Alphabet[remain shr 3]; remain:=remain and $7; end;
			2: begin
				back:=back+Base32Alphabet[remain shr 6]; remain:=remain and $3F;
				back:=back+Base32Alphabet[remain shr 1]; remain:=remain and $1;
			end;
			3: begin back:=back+Base32Alphabet[remain shr 4]; remain:=remain and $F; end;
			4: begin
				back:=back+Base32Alphabet[remain shr 7]; remain:=remain and $7F;
				back:=back+Base32Alphabet[remain shr 2]; remain:=remain and $3;
			end;	
		end;
	end;
	exit(back);
End;

Function Base32_Decode(a:string):string;
Var
	i : longint;
	back : string;
	
	remain : longint;
	scan : longint;
	tmp : longint;
Begin
	back:='';
	scan:=0;
	remain:=0;
	for i:=1 to length(a) do begin
		if ('a' <= a[i]) and (a[i] <= 'z') then begin
			a[i] := char(longint(a[i]) - 32); //A$41 a$61
		end;
		
		tmp := pos(a[i],Base32Alphabet)-1;
		if tmp<0 then raise Base32Exception_InvalidLetter.Create(format('Letter %s (%d) was found in pos %d',[a[i],longint(a[i]),i]));
		remain:=remain*32+tmp;
		inc(scan);
		
		case scan mod 8 of
			0: begin back:=back+char(remain); remain:=0; end;
			2: begin back:=back+char(remain shr 2); remain:=remain and $3; end;
			4: begin back:=back+char(remain shr 4); remain:=remain and $F; end;
			5: begin back:=back+char(remain shr 1); remain:=remain and $1; end;
			7: begin back:=back+char(remain shr 3); remain:=remain and $7; end;
		end;
		
	end;
	
	exit(back);
End;

procedure Base32_Init();
Var
	s : string;
	i : longint;
Begin
	s:='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	for i:=1 to 32 do begin
		Base32Alphabet[i-1]:=s[i];
	end;
End;


Function GoogleAuthenticatorCode_Gen(secret:string;time:int64):string;overload;
Var
	msg	: string;
	hash : THMACSHA1Digest;
	
	offset : longint;
	truncatedHash : int64;
	
	back : string;
Begin
	secret:=Base32_Decode(secret);
	
	msg:='';
	while time>0 do begin
		msg:=char(time mod 256)+msg;
		time:=time div 256;
	end;
	while length(msg)<8 do msg:=char(0)+msg;
	
	hash := HMACSHA1Digest(secret,msg);
	
	offset := hash[19] and $F;
	truncatedHash:=((hash[offset]*256*256*256 + hash[offset+1]*256*256 + hash[offset+2]*256 + hash[offset+3]) and $7FFFFFFF) mod 1000000;
	
	back:=IntToStr(truncatedHash);
	while length(back)<6 do back:='0'+back;
	
	exit(back);
End;


Function GoogleAuthenticatorCode_Gen(secret:string):string;overload;
Var
	time : longint;
Begin
	time:=DateTimeToUnix(LocalTimeToUniversal(Now())) div 30;
	exit(GoogleAuthenticatorCode_Gen(secret,time));
End;

Function GoogleAuthenticatorCode_Verfy(const secret,submit:string):boolean;
Var
	time : longint;
	i : longint;
Begin
	time:=DateTimeToUnix(LocalTimeToUniversal(Now())) div 30;
	for i:=time-1 to time+1 do begin
		if submit = GoogleAuthenticatorCode_Gen(secret,i) then exit(true);
	end;
	exit(false);
End;

Function GoogleAuthenticatorCode_GenerateASecret:string;
Var
	Secret : string;
	i : longint;
Begin
	Secret:='';
	for i:=1 to 8 do Secret:=Secret+char(random(256));
	Secret:=Base32_Encode(Secret);
	exit(Secret);
End;


Initialization
randomize;
Base32_Init();

End.