function test1 (a,b)
Local a1:=0, a2:=1, a3:=127, a4:=-127, a5:=1114556 , a6:=-1114556
Local a7:=1234567.890123, a8:=-1234567.890123

Local a9:={},a10:={0,1,127,-127,1114556,-1114556,1234567.890123,-1234567.890123}
Local a11:=1, a12:=10,j:=0, a13:=.t.,a14:=.f.
Local i:=0,k:=4
for j:=a11 to a12
 for k:= 3 to a3
  for i= 1 to 10
      a1:=a1+1
  next i
 next k
next j
return nil
