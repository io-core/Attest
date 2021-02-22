(* begin-module-short-description
provides routines for handling key pairs.
end-module-short-description *)

(* begin-module-use-description
Module KeyPairs provides the data structures used by the Attest package for code provenance.

end-module-use-description *)
MODULE KeyPairs;
  IMPORT SYSTEM, Kernel, Oberon;

  CONST

  TYPE
    KeyPair* = POINTER TO KeyPairDesc;
    KeyPairDesc* = RECORD
      value*: INTEGER;
      next: KeyPair
    END;

  VAR

PROCEDURE New*(P: KeyPair; v: INTEGER) : KeyPair;
BEGIN
  IF P = NIL THEN NEW(P) END;
  IF P # NIL THEN
    P.value := v;
    P.next := NIL
  END
  RETURN P 
END New;

PROCEDURE Get*(P: KeyPair; x: INTEGER): INTEGER;
  VAR r,i: INTEGER; P1:KeyPair;
BEGIN i:=0;r:=0;
  P1:=P; WHILE P1 # NIL DO 
    IF i = x THEN r := P1.value END;
    P1:=P1.next;
    INC(i)
  END
  RETURN r 
END Get;

PROCEDURE Clear*(P: KeyPair);
BEGIN
  P.value:=0;
  P.next:=NIL
END Clear;

BEGIN
END KeyPairs.
