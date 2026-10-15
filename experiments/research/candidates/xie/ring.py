"""Exact bounded negacyclic arithmetic for the Xie equation study."""


def coefficients(value,n,*,modulus=None,bits=31):
    if type(value) not in (tuple,list) or len(value)!=n:raise ValueError("polynomial dimension")
    if any(type(x) is not int or abs(x).bit_length()>bits for x in value):raise ValueError("polynomial integer bound")
    if modulus is not None and any(not 0<=x<modulus for x in value):raise ValueError("noncanonical residue")
    return tuple(value)


def add(a,b,q=None):
    if len(a)!=len(b):raise ValueError("polynomial dimension")
    return tuple((x+y)%q if q else x+y for x,y in zip(a,b))


def neg(a):return tuple(-x for x in a)


def mul(a,b,q=None):
    n=len(a)
    if len(b)!=n:raise ValueError("polynomial dimension")
    result=[0]*n
    for i,x in enumerate(a):
        for j,y in enumerate(b):
            if i+j<n:result[i+j]+=x*y
            else:result[i+j-n]-=x*y
    return tuple(x%q if q else x for x in result)


def rotations(a):
    result=[];a=tuple(a)
    for _ in a:
        result.append(a);a=(-a[-1],)+a[:-1]
    return tuple(result)


def inverse(a,q):
    """Extended Euclid over Fq[x]; reject zero divisors instead of field division."""
    n=len(a)
    def trim(p):
        p=[x%q for x in p]
        while p and not p[-1]:p.pop()
        return p
    def subtract(a,b):return trim([(a[i] if i<len(a) else 0)-(b[i] if i<len(b) else 0) for i in range(max(len(a),len(b)))])
    def product(a,b):
        if not a or not b:return []
        r=[0]*(len(a)+len(b)-1)
        for i,x in enumerate(a):
            for j,y in enumerate(b):r[i+j]=(r[i+j]+x*y)%q
        return trim(r)
    def divide(a,b):
        a=trim(a);quot=[0]*max(0,len(a)-len(b)+1);leading=pow(b[-1],-1,q)
        while len(a)>=len(b) and a:
            k=len(a)-len(b);v=a[-1]*leading%q;quot[k]=v
            a=subtract(a,[0]*k+[(v*x)%q for x in b])
        return trim(quot),a
    r0=[1]+[0]*(n-1)+[1];r1=trim(a);s0=[];s1=[1]
    while r1:
        quotient,remainder=divide(r0,r1)
        r0,r1=r1,remainder;s0,s1=s1,subtract(s0,product(quotient,s1))
    if len(r0)!=1:raise ValueError("nonunit polynomial")
    scale=pow(r0[0],-1,q);out=[0]*n
    for i,x in enumerate(s0):out[i%n]+=((-1)**(i//n))*x*scale
    result=tuple(x%q for x in out)
    if mul(a,result,q)!=(1,)+(0,)*(n-1):raise ValueError("inverse check failed")
    return result


def prime(q):
    if type(q) is not int or q<2:return False
    if q%2==0:return q==2
    p=3
    while p*p<=q:
        if q%p==0:return False
        p+=2
    return True
