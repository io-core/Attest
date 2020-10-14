(* begin-module-description
Module KeySafes keeps the secrets used to sign and trust signed code.

end-module-description *)
MODULE KeySafes;

  IMPORT SYSTEM, Files, Fonts, KeyPairs;

  CONST 
    replace* = 0; insert* = 1; delete* = 2; unmark* = 3;  (*op-codes*)

  TYPE 
    Method* = POINTER TO MethodDesc;
    KeyRing* = POINTER TO KeyRingDesc;
    KeyRingDesc* = RECORD
      x*, y*, w*, h*, d*, p*: INTEGER;
      sx*, sy*: REAL;
      sw*, sh*: INTEGER;
      selected*, marked*: BOOLEAN;
      do*: Method;
      next: KeyRing
    END;

    KeySafe* = POINTER TO KeySafeDesc;
    Notifier* = PROCEDURE (S: KeySafe; op: INTEGER; beg, end: LONGINT);
    KeySafeDesc* = RECORD
      len*: LONGINT;
      changed*: BOOLEAN;
      flattened*: BOOLEAN;
      sel*, first: KeyRing;
      notify*: Notifier
    END;

    Msg* = RECORD END ;
    WidMsg* = RECORD (Msg) w*: INTEGER END ;
    ColorMsg* = RECORD (Msg) col*: INTEGER END ;
    FontMsg* = RECORD (Msg) fnt*: Fonts.Font END ;
    

    bmpHeaderEntry = RECORD
        a: INTEGER;
        b: INTEGER;
        c: INTEGER;
        d: INTEGER
    END;

    jpgHeaderEntry = RECORD
        a: INTEGER;
        b: INTEGER;
        c: INTEGER;
        d: INTEGER
    END;

    pngHeaderEntry = RECORD
        a: INTEGER;
        b: INTEGER;
        c: INTEGER;
        d: INTEGER
    END;

    MethodDesc* = RECORD
(*        module*, allocator*: Name;
        new*: Modules.Command;             *)
        copy*: PROCEDURE (from, to: KeyRing);
        draw*, change*: PROCEDURE (R: KeyRing; VAR msg: Msg);
        selectable*: PROCEDURE (R: KeyRing; x, y: INTEGER): BOOLEAN;
        read*: PROCEDURE (R: KeyRing; VAR r: Files.Rider); (*; VAR c: Context); *)
        write*: PROCEDURE (R: KeyRing; cno: INTEGER; VAR r: Files.Rider); (*; VAR c: Context);*)
        print*: PROCEDURE (R: KeyRing; x, y: INTEGER)
      END ;

    
VAR 
 
  res*: INTEGER;
  width: INTEGER;
  new*: KeyRing; 
  LineMethod*, CapMethod*, MacMethod* : Method;

  PROCEDURE New*(R: KeyRing);
  BEGIN   new := R 
  END New;

  PROCEDURE Add*(S: KeySafe; R: KeyRing);
  BEGIN R.marked := FALSE; R.selected := TRUE; R.next := S.first;
    S.first := R; S.sel := R; S.changed := TRUE
  END Add;

  PROCEDURE ThisKeyRing*(S: KeySafe; x, y: INTEGER): KeyRing;
    VAR R: KeyRing;
  BEGIN R := S.first;
    WHILE (R # NIL) & ~R.do.selectable(R, x ,y) DO R := R.next END ;
    RETURN R
  END ThisKeyRing;

  PROCEDURE SelectKeyRing*(S: KeySafe; R: KeyRing);
  BEGIN
    IF R # NIL THEN R.selected := TRUE; S.sel := R END
  END SelectKeyRing;

  PROCEDURE SelectArea*(S: KeySafe; x0, y0, x1, y1: INTEGER);
    VAR R: KeyRing; t: INTEGER;
  BEGIN R := S.first;
    IF x1 < x0 THEN t := x0; x0 := x1; x1 := t END ;
    IF y1 < y0 THEN t := y0; y0 := y1; y1 := t END ;
    WHILE R # NIL DO
      IF (x0 <= R.x) & (R.x + R.w <= x1) & (y0 <= R.y) & (R.y + R.h <= y1) THEN
        R.selected := TRUE; S.sel := R
      END ;
      R := R.next
    END ;
    IF S.sel # NIL THEN  END
  END SelectArea;

  PROCEDURE Draw*(S: KeySafe; VAR m: Msg);
    VAR R: KeyRing;
  BEGIN R := S.first;
    WHILE R # NIL DO R.do.draw(R, m); R := R.next END
  END Draw;

(*
  PROCEDURE List*(S: KeySafe);
    VAR R: KeyRing; tag: INTEGER;
  BEGIN R := S.first;
    WHILE R # NIL DO
      Texts.Write(XW, 9X); Texts.WriteHex(XW, ORD(R)); Texts.Write(XW, 9X);
      Texts.WriteInt(XW, R.x, 5); Texts.WriteInt(XW, R.y, 5); Texts.WriteInt(XW, R.w, 5); Texts.WriteInt(XW, R.h, 5);
      Texts.Write(XW, "/"); SYSTEM.GET(ORD(R)-8, tag); Texts.WriteHex(XW, tag);
      SYSTEM.GET(ORD(R)-4, tag); Texts.WriteHex(XW, tag); Texts.WriteLn(XW); R := R.next
    END ;
    Texts.Append(Oberon.Log, XW.buf)
  END List;
*)

  (*----------------procedures operating on selection -------------------*)

  PROCEDURE Deselect*(S: KeySafe);
    VAR R: KeyRing;
  BEGIN R := S.first; S.sel := NIL; 
    WHILE R # NIL DO R.selected := FALSE; R := R.next END
  END Deselect;

  PROCEDURE DrawSel*(S: KeySafe; VAR m: Msg);
    VAR R: KeyRing;
  BEGIN R := S.first;
    WHILE R # NIL DO
      IF R.selected THEN R.do.draw(R, m) END ;
      R := R.next
    END
  END DrawSel;

  PROCEDURE Change*(S: KeySafe; VAR m: Msg);
    VAR R: KeyRing;
  BEGIN R := S.first; S.changed := TRUE;
    WHILE R # NIL DO
      IF R.selected THEN R.do.change(R, m) END ;
      R := R.next
    END
  END Change;



  PROCEDURE WriteFile*(S: KeySafe; name: ARRAY OF CHAR);
    VAR f: Files.File; w: Files.Rider; 
  BEGIN f := Files.New(name); Files.Set(w, f, 0); 
  (*  Files.Write(w, GraphFileId); InitContext(c); StoreElems(w, c, S.first);  *)
    Files.Register(f)
  END WriteFile;


  PROCEDURE SetWidth*(w: INTEGER);
  BEGIN width := w
  END SetWidth;


  PROCEDURE Open*(S: KeySafe; name: ARRAY OF CHAR);
    VAR tag: CHAR;
          b: BYTE;
          i: INTEGER;
      f: Files.File; r: Files.Rider; 
  BEGIN S.first := NIL; S.sel := NIL; S.changed := FALSE; f := Files.Old(name);
    IF f # NIL THEN
      Files.Set(r, f, 0);
      Files.ReadByte(r, b); i:=b;
      Files.ReadByte(r, b); i:=i+(b*100H);
     
    ELSE res := 2
    END
  END Open;



  PROCEDURE Delete*(S: KeySafe);
    VAR R, pred: KeyRing;
  BEGIN S.sel := NIL; S.changed := TRUE; R := S.first;
    WHILE (R # NIL) & R.selected DO R := R.next END ;
    S.first := R;
    IF R # NIL THEN
      pred := R; R := R.next;
      WHILE R # NIL DO
        IF R.selected THEN pred.next := R.next ELSE pred := R END ;
        R := R.next
      END
    END
  END Delete;






  PROCEDURE InstallDrawMethods*(drawLine, drawCaption, drawMacro: PROCEDURE (R: KeyRing; VAR msg: Msg));
  BEGIN LineMethod.draw := drawLine; CapMethod.draw := drawCaption; MacMethod.draw := drawMacro
  END InstallDrawMethods;

BEGIN 
END KeySafes.

