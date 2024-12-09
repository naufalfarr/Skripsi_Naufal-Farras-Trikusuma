text = "Python"
user_input = input("Masukkan kata kunci: ") 
result = " "

if user_input == text.lower():
     result = "Match"
elif user_input == text.upper():
     result = "CaseSensitiveMatch" 
else:
     result = "NoMatch"
print(result)