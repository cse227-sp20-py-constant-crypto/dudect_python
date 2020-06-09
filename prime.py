from test_lib import generate_zero_message
import sympy
def generate_prime_key(n):
    for i in range(2**(8*n), 2**(8*n+1)):
        if isPrime(i):
            print("The generated prime key with length of {length} is {number}".format(length=8*n, number=i))
            return bin(i).replace("0b","") 
    return generate_zero_message(n)

def isPrime(n) : 
    if (n <= 1) : 
        return False
    if (n <= 3) : 
        return True
    if (n % 2 == 0 or n % 3 == 0) : 
        return False
    i = 5
    while(i * i <= n) : 
        if (n % i == 0 or n % (i + 2) == 0) : 
            return False
        i = i + 6
    return True

# print(generate_prime_key(8))
def generate_prime_message(n):
    prime_number = sympy.randprime(2**(8*n-1), 2**(8*n))
    prime_number_bin = bin(prime_number).replace("0b","") 
    print(prime_number_bin)
    print(prime_number)
    return prime_number_bin

print(len(str(generate_prime_message(16))))