import os

class menu:
    """ Used to create a menu, with options to execute funcions (with no arguments) """
    
    def clear_output():
        os.system("clear || cls")

    def __init__(self, options : list, choice_msg = "", warn_input_msg = """Invalid input! Type again""", init_msg = None):
        """
        options: the list of options to execute, in the form [(description, function)]

        choice_msg: a string to display to the user, asking him to choose an option from the possible ones.

        warn_input_msg: a string with a warning message.

        init_msg: a string with a initial message, displayed to the user before the options
        """
        
        # A dict in the form {key: string, (opt_description: string, action: function)}
        self.opt_menu = dict()
        self.warning_input_msg = warn_input_msg
        self.init_msg = init_msg
        self.choice_msg = choice_msg

        options.append(("Exit", lambda: 0))

        # Initializing the options menu
        for cont in range(1, len(options) + 1):
            self.opt_menu[str(cont)] = options[cont - 1]

    def print_options(self):
        """ Display the options to the user. """
        
        if self.init_msg != None:
            print("\n" + self.init_msg)
        # A list of strings
        descriptions = []

        # Formating the options
        for key_option in self.opt_menu:
            descr_str = key_option+ ' : ' + self.opt_menu[key_option][0] + ';'

            descriptions.append(descr_str)

        for desc in descriptions:
            
            print(desc, sep = '\n')

    def get_input(self):
        """ Get a user input, validating the value. """
        
        print('\n' + self.choice_msg)
        get_option = input("\n> ")

        while get_option not in self.opt_menu.keys():
            print(self.warning_input_msg)
            get_option = input("\n> ")

        return get_option

    def execute_opt(self):
        """ Executes a specific option chosed. """
        opt = self.get_input()

        print('---', self.opt_menu[opt][0], '---')
        # Calling the chosed option
        return self.opt_menu[opt][1]()

    def execute(self):
        """ Executes the menu class instance """
        
        self.print_options()
        return self.execute_opt()
        # os.system("clear || cls")