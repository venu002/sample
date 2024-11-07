import  inquirer

def main():
    questions = [
     inquirer.List("options",
                   message="select add or remove",
                   choices=["add","Remove","exit"],
                   carousel=True
                   ),  
    ]
    
    options = inquirer.prompt(questions)['options']
    
    print(options)