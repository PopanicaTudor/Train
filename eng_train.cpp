#include <iostream>
#include <fstream>
#include <random>
#include <ctime>
#include <regex>

using namespace std;

/// CLASSES
class AccountManager // The AccountManager class is an abstract class that contains methods for generating a random key, encrypting the password, and checking password strength
{
protected:
    string generateRandomKey(int length) // Method for generating a random key
    {                                    // Generate a random key of the length given by the parameter length (password length)
        string key = ""; // Generated key
        random_device rd; // Random number generator
        mt19937 gen(rd()); // Random number generator
        uniform_int_distribution<> distr(0, 25); // Uniform distribution of integers between 0 and 25

        for (int i = 0; i < length; i++) 
        {
            key += 'A' + distr(gen); // Add a random character between 'A' and 'Z' to the key
        }
        return key; // Return the generated key
    }

    string vigenereEncrypt(string text, string key) // Method for encrypting the password
    {
        string encryptedText = ""; // Encrypted text

        for (int i = 0; i < text.size(); i++)
        {
            char base = islower(text[i]) ? 'a' : 'A'; // Base character to determine if the text is lowercase or uppercase

            encryptedText += (text[i] - base + (key[i % key.size()] - 'A')) % 26 + base; // Encrypt the text
        }

        return encryptedText; // Return the encrypted text
    }

    string checkPasswordStrength(const string &password) // Method for checking password strength
    {
        if (password.length() < 8) // If the password length is less than 8 characters
        {
            return "weak"; // The password is weak
        }

        bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false; // Variables to check if the password contains lowercase, uppercase, digits, or special characters
        string specialChars = "!@#$%^&*()-+"; // Special characters

        for (char ch : password)
        {
            if (islower(ch))
                hasLower = true;
            else if (isupper(ch))
                hasUpper = true;
            else if (isdigit(ch))
                hasDigit = true;
            else if (specialChars.find(ch) != string::npos)
                hasSpecial = true;
        }

        if (hasLower && hasUpper && hasDigit && hasSpecial) // If the password contains lowercase, uppercase, digits, and special characters
        {
            return "strong"; // The password is strong
        }
        else if ((hasLower || hasUpper) && (hasDigit || hasSpecial)) // If the password contains lowercase or uppercase and digits or special characters
        {
            return "ok"; // The password is ok
        }
        else
        {
            return "weak"; // The password is weak
        }
    }

    int login(string fileName, string &inputEmail) // Method for logging in a user/operator
    {
        string inputPass;
        cout << "Enter email: ";
        getline(cin, inputEmail);
        cout << "Enter password: ";
        getline(cin, inputPass);

        ifstream operatorsFile(fileName);
        if (!operatorsFile.is_open())
        {
            cerr << "Unable to open operators file!" << endl;
            return -1;
        }

        string line, storedEmail, storedEncryptedPass, storedKey;
        bool emailFound = false;

        getline(operatorsFile, line); // Read the header line

        while (getline(operatorsFile, line)) // Read each line from the file
        {                                    // Check if the email entered by the user is found in the file
            size_t pos1 = line.find(',');
            size_t pos2 = line.rfind(',');

            storedEmail = line.substr(0, pos1);
            storedEncryptedPass = line.substr(pos1 + 1, pos2 - pos1 - 1);
            storedKey = line.substr(pos2 + 1);

            if (storedEmail == inputEmail)
            {
                emailFound = true; // If the email is found in the file, set emailFound to true
                break; // Exit the loop
            }
        }

        operatorsFile.close();

        if (!emailFound) // If the email entered by the user is not found in the file
        {
            throw "Incorrect email!"; // Throw an error message
        }

        string encryptedInputPass = vigenereEncrypt(inputPass, storedKey); // Encrypt the password entered by the user

        if (encryptedInputPass == storedEncryptedPass) // If the encrypted password entered by the user matches the encrypted password in the file
        {
            cout << endl
                 << "Login successful!" << endl; // Display a success message
            return 1; // Return 1, login was successful
        }
        else
        {
            throw "Incorrect password!"; // Otherwise, throw an error message
        }
    }

    int registerUser(string fileName, string &email) // Method for registering a user
    {
        string pass, confirmPass, passStrength;
        cout << "Enter email: ";
        getline(cin, email);
        cout << "Enter password: ";
        getline(cin, pass);
        cout << "Confirm password: ";
        getline(cin, confirmPass);

        if (email.empty() || pass.empty() || confirmPass.empty())
        {
            throw "Please fill in all fields!";
        }
        else if (email.find('@') == string::npos || email.find('.') == string::npos) // Check if the email entered by the user contains @ and .
        {
            throw "Invalid email address! Please try again.";
        }
        else if (!regex_match(email, regex(R"(^[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}$)"))) // Check if the email entered by the user matches the regex pattern
        {
            throw "Invalid email address! Please try again.";
        }
        else if (pass != confirmPass) // Check if the two passwords entered by the user match
        {
            throw "Passwords do not match! Retry registration.";
        }
        else
        {
            passStrength = checkPasswordStrength(pass); // Check the strength of the password entered by the user

            if (passStrength == "weak") // If the password is weak
            {
                throw "Password is too weak! Please try again and use a stronger password."; // Throw an error message
            }
        }

        ofstream usersFile(fileName, ios::app);
        if (usersFile.is_open())
        {
            string key = generateRandomKey(pass.length());
            string encryptedPass = vigenereEncrypt(pass, key);

            usersFile << email << "," << encryptedPass << "," << key << endl; // Write the user's data to the file
            usersFile.close();

            cout << endl
                 << "User registered successfully! Password strength: " << passStrength << endl; // Display a success message
            return 1;
        }
        else
        {
            throw "Unable to open users file!"; // Otherwise, throw an error message
        }
    }
};

class TrainRoute // The TrainRoute class contains methods for adding and deleting a route, checking the validity of a date and a city
{
public:
    string departure;
    string destination;
    string date;

    TrainRoute() {}

    TrainRoute(string departure, string destination, string date)
    {
        this->departure = departure;
        this->destination = destination;
        this->date = date;
    }

    bool isValidDate(const string &date) // Method for checking the validity of a date
    {
        regex datePattern("^\\d{2}/\\d{2}/\\d{4}$"); // Pattern for date in the format DD/MM/YYYY
        if (!regex_match(date, datePattern)) // Check if the date entered by the user matches the pattern
        {
            return false;
        }

        int day = stoi(date.substr(0, 2)); // Extract the day from the date entered by the user
        int month = stoi(date.substr(3, 2)); // Extract the month from the date entered by the user
        int year = stoi(date.substr(6, 4)); // Extract the year from the date entered by the user

        if (month < 1 || month > 12 || day < 1 || day > 31) // Check if the month and day are in the correct range
        {
            return false;
        }

        int daysInMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}; // Number of days in each month

        if (month == 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) // If the year is a leap year
        {
            daysInMonth[1] = 29; // Set the number of days in February to 29
        }

        if (day > daysInMonth[month - 1]) // Check if the day entered by the user is valid
        {
            return false;
        }

        time_t t = time(0); // Get the current time
        tm *now = localtime(&t); // Get the current date

        int currentYear = now->tm_year + 1900;
        int currentMonth = now->tm_mon + 1;
        int currentDay = now->tm_mday;

        if (year < currentYear ||
           (year == currentYear && month < currentMonth) ||
           (year == currentYear && month == currentMonth && day < currentDay)) // Check if the date entered by the user is in the past
        {
            return false;
        }

        return true;
    }

    bool isValidCity(const string &city) // Method for checking the validity of a city
    {
        regex cityPattern("^[a-zA-Z]+(?:[\\s-][a-zA-Z]+)*$"); // Pattern for city, which can contain uppercase and lowercase letters, spaces, and hyphens, but no other special characters
        return regex_match(city, cityPattern);                // Check if the city entered by the user matches the pattern
    }

    void addRoute(string departure, string destination, string date) // Method for adding a route
    {
        ofstream routesFile("routes.csv", ios::app);
        if (routesFile.is_open())
        {
            routesFile << departure << "," << destination << "," << date << endl; // Write the route data to the file
            routesFile.close();
        }
        else
        {
            cerr << "Unable to open routes file!" << endl;
        }
        routesFile.close();
    }

    void deleteRoute(string departure, string destination, string date) // Method for deleting a route
    {
        ifstream routesFile("routes.csv");
        if (!routesFile.is_open())
        {
            cerr << "Unable to open routes file!" << endl;
            return;
        }

        string line, storedDeparture, storedDestination, storedDate;
        bool routeFound = false;

        getline(routesFile, line); // Read the header line

        while (getline(routesFile, line)) // Read each line from the file
        {
            size_t pos1 = line.find(',');
            size_t pos2 = line.rfind(',');

            storedDeparture = line.substr(0, pos1);
            storedDestination = line.substr(pos1 + 1, pos2 - pos1 - 1);
            storedDate = line.substr(pos2 + 1);

            if (storedDeparture == departure && storedDestination == destination && storedDate == date) // Check if the route is found in the file
            {
                routeFound = true;
                break;
            }
        }

        routesFile.close();

        if (!routeFound)
        {
            throw "Route not found!";
        }

        ifstream inputFile("routes.csv");
        ofstream tempFile("temp.csv");

        if (!inputFile.is_open() || !tempFile.is_open())
        {
            cerr << "Unable to open files for deletion process!" << endl;
            return;
        }

        tempFile << "departure,destination,date" << endl; // Write the header to the temporary file

        getline(inputFile, line); // Read the header from the original file

        while (getline(inputFile, line)) // Read each line from the original file
        {
            if (line != storedDeparture + "," + storedDestination + "," + storedDate) // If the line read is not the one we want to delete
            {
                tempFile << line << endl; // Write the line to the temporary file
            }
        }

        inputFile.close();
        tempFile.close();

        remove("routes.csv"); // Delete the original file
        rename("temp.csv", "routes.csv"); // Rename the temporary file to the original file

        cout << endl
             << "Route deleted successfully: " << departure << " to " << destination << " on " << date << endl; // Display a success message
    }
};

class Operator : public AccountManager, public TrainRoute // The Operator class inherits methods from AccountManager and TrainRoute classes
{                                                         // Contains methods for adding and deleting a route, as well as for logging in an operator
private:
    string email;
    string pass;
    string file = "operators.csv";

public:
    Operator() {}

    Operator(string email, string pass)
    {
        this->email = email;
        this->pass = pass;

        ofstream operatorsFile("operators.csv", ios::app);
        if (operatorsFile.is_open())
        {
            string key = generateRandomKey(pass.length());
            string encryptedPass = vigenereEncrypt(pass, key);

            operatorsFile << email << "," << encryptedPass << "," << key << endl;
            operatorsFile.close();
        }
        else
        {
            cerr << "Unable to open operators file!" << endl;
        }
    }

    int login() // Method for logging in an operator
    {
        cout << endl
             << "-----OPERATOR LOGIN-----" << endl;

        return (AccountManager::login(file, email) == 1);
    }

    void addRoute() // Method for adding a route
    {
        cout << endl
             << "------NEW ROUTE------" << endl;

        cout << "Departure: ";
        string departure;
        getline(cin, departure);

        cout << "Destination: ";
        string destination;
        getline(cin, destination);

        cout << "Date (DD/MM/YYYY): ";
        string date;
        getline(cin, date);

        if (!TrainRoute::isValidDate(date)) // Check if the date entered by the operator is valid
        {
            throw "Invalid date format/date is in the past!";
        }

        if (!isValidCity(departure) || !isValidCity(destination)) // Check if the cities entered by the operator are valid
        {
            throw "Invalid city name(s)! Please try again.";
        }

        TrainRoute::addRoute(departure, destination, date); // Add the route to the file

        cout << endl
             << "Route added successfully: " << departure << " to " << destination << " on " << date << endl; // Display a success message
    }

    void deleteRoute() // Method for deleting a route
    {
        cout << endl
             << "-----DELETE ROUTE-----" << endl;

        cout << "Departure: ";
        string departure;
        getline(cin, departure);

        cout << "Destination: ";
        string destination;
        getline(cin, destination);

        cout << "Date (DD/MM/YYYY): ";
        string date;
        getline(cin, date);

        if (!isValidDate(date)) // Check if the date entered by the operator is valid
        {
            throw "Invalid date format/date is in the past!";
        }

        if (!isValidCity(departure) || !isValidCity(destination)) // Check if the cities entered by the operator are valid
        {
            throw "Invalid city name(s)! Please try again.";
        }

        TrainRoute::deleteRoute(departure, destination, date); // Delete the route from the file
    }
};

class User : public AccountManager, public TrainRoute // The User class inherits methods from AccountManager and TrainRoute classes
{
private:
    string email;
    string pass;
    string file = "users.csv";

public:
    User() {}

    User(string email, string pass)
    {
        this->email = email;
        this->pass = pass;
    }

    int registerUser() // Method for registering a user
    {
        string email;

        cout << endl
             << "-----USER REGISTRATION-----" << endl;

        int succesfulRegistration = (AccountManager::registerUser(file, email) == 1); // Call the method for registering a user
        if (succesfulRegistration)
        {
            this->email = email; // Set the user's email
        }

        return succesfulRegistration; // Return 1 if registration was successful
    }

    int login() // Method for logging in a user
    {
        string email;

        cout << endl
             << "------USER LOGIN------" << endl;

        int succesfulLoggin = (AccountManager::login(file, email) == 1); // Call the method for logging in a user
        if (succesfulLoggin)
        {
            this->email = email; // Set the user's email
        }

        return succesfulLoggin; // Return 1 if login was successful
    }

    int findRoute(string departure, string destination, string date) // Method for searching a route
    {
        ifstream routesFile("routes.csv");
        if (!routesFile.is_open())
        {
            cerr << "Unable to open routes file!" << endl;
            return -1;
        }

        string line, storedDeparture, storedDestination, storedDate;
        bool routeFound = false;

        getline(routesFile, line); // Read the header line

        while (getline(routesFile, line)) // Read each line from the file
        {
            size_t pos1 = line.find(',');
            size_t pos2 = line.rfind(',');

            storedDeparture = line.substr(0, pos1);
            storedDestination = line.substr(pos1 + 1, pos2 - pos1 - 1);
            storedDate = line.substr(pos2 + 1);

            if (storedDeparture == departure && storedDestination == destination && storedDate == date) // Check if the route is found in the file
            {
                routeFound = true; // If the route is found in the file, set routeFound to true
                break;
            }
        }

        routesFile.close();

        if (routeFound)
        {
            cout << endl
                 << "Route found: " << departure << " to " << destination << " on " << date << endl; // Display a success message
            return 1;
        }
        else
        {
            throw "Route not found!"; // Otherwise, throw an error message
        }
    }

    void bookTicket() // Method for booking a ticket
    {
        cout << endl
             << "-----BOOK TICKET-----" << endl;

        cout << "Departure: ";
        string departure;
        getline(cin, departure);

        cout << "Destination: ";
        string destination;
        getline(cin, destination);

        cout << "Date (DD/MM/YYYY): ";
        string date;
        getline(cin, date);

        if (!TrainRoute::isValidDate(date)) // Check if the date entered by the user is valid
        {
            throw "Invalid date format/date is in the past!";
        }

        if (!isValidCity(departure) || !isValidCity(destination)) // Check if the cities entered by the user are valid
        {
            throw "Invalid city name(s)! Please try again.";
        }

        if (findRoute(departure, destination, date) == 1) // Check if the route is available
        {
            cout << "Route is available!" << endl << endl
                 << "What class do you want?" << endl
                 << "1. First Class" << endl
                 << "2. Second Class" << endl
                 << "3. Business Class" << endl
                 << "4. Economy Class" << endl
                 << endl
                 << "Choose an option: ";
            int choice;
            cin >> choice;
            cin.ignore();

            cout << endl;

            while (choice < 1 || choice > 4) // Check if the option chosen by the user is valid
            {
                cout << "Invalid option. Please try again." << endl
                     << "Choose an option: ";
                cin >> choice;
                cin.ignore();
            }
            string classOption;
            switch (choice) // Set the class according to the option chosen by the user
            {
            case 1:
                classOption = "First Class";
                break;
            case 2:
                classOption = "Second Class";
                break;
            case 3:
                classOption = "Business Class";
                break;
            case 4:
                classOption = "Economy Class";
                break;
            }

            cout << "Choose an hour (0-23): "; // Enter the hour
            int hour;
            cin >> hour;
            cin.ignore();

            while (hour < 0 || hour > 23) // Check if the hour entered by the user is valid
            {
                cout << "Invalid hour. Please try again." << endl
                     << "Choose an hour: ";
                cin >> hour;
                cin.ignore();
            }

            ofstream ticketsFile("tickets.csv", ios::app);
            if (ticketsFile.is_open())
            {
                ticketsFile << email << "," << departure << "," << destination << "," << date << "," << classOption << "," << hour << endl; // Write the ticket data to the file
                ticketsFile.close();

                cout << endl
                     << "Ticket booked successfully!" << endl
                     << "Departure: " << departure << endl
                     << "Destination: " << destination << endl
                     << "Date: " << date << endl
                     << "Class: " << classOption << endl
                     << "Hour: " << hour << endl;
            }
            else
            {
                throw "Unable to open tickets file!"; // Otherwise, throw an error message
            }
        }
    }
};

/// MENU
int mainMenu() // Main menu
{
    cout << endl
         << "------MAIN MENU------" << endl
         << "1. Operator" << endl
         << "2. User" << endl
         << "3. Exit" << endl
         << endl
         << "Choose an option: ";
    int choice;
    cin >> choice;
    cin.ignore();
    return choice;
}

void operatorMenu(Operator &op) // Menu for operator
{
    while (true)
    {
        cout << endl
             << "-----OPERATOR MENU-----" << endl
             << "1. Add Route" << endl
             << "2. Delete Route" << endl
             << "3. Logout" << endl
             << endl
             << "Choose an option: ";
        int choice;
        cin >> choice;
        cin.ignore();

        try
        {
            switch (choice)
            {
            case 1:
                op.addRoute();
                break;
            case 2:
                op.deleteRoute();
                break;
            case 3:
                return;
            default:
                throw "Invalid option. Please try again.";
                break;
            }
        }
        catch (const char *msg)
        {
            cerr << endl
                 << msg << endl;
        }
    }
}

void userMenu(User &user) // Menu for user
{
    bool loggedIn = false;

    while (true)
    {
        cout << endl
             << "-----USER MENU-----" << endl
             << "1. Register" << endl
             << "2. Login" << endl
             << "3. Search Route" << endl
             << "4. Book Ticket" << endl
             << "5. Logout" << endl
             << endl
             << "Choose an option: ";
        int choice;
        cin >> choice;
        cin.ignore();

        try
        {
            string departure, destination, date;
            switch (choice)
            {
            case 1:
                if (user.registerUser() == 1)
                {
                    loggedIn = true;
                }
                break;
            case 2:
                if (user.login() == 1)
                {
                    loggedIn = true;
                }
                break;
            case 3:
                if (!loggedIn)
                {
                    throw "Please login first!";
                }
                
                cout << endl
                        << "-----Search Route-----" << endl;
                
                cout << "Departure: ";
                getline(cin, departure);

                cout << "Destination: ";
                getline(cin, destination);

                cout << "Date (DD/MM/YYYY): ";
                getline(cin, date);

                if (!user.isValidDate(date))
                {
                    throw "Invalid date format/date is in the past!";
                }

                if (!user.isValidCity(departure) || !user.isValidCity(destination))
                {
                    throw "Invalid city name(s)! Please try again.";
                }

                if (user.findRoute(departure, destination, date) == 1)
                {
                    cout << "Route is available!" << endl;
                }
                else
                {
                    throw "Route not found!";
                }
                break;
            case 4:
                if (!loggedIn)
                {
                    throw "Please login first!";
                }
                user.bookTicket();
                break;
            case 5:
                return;
            default:
                throw "Invalid option. Please try again.";
                break;
            }
        }
        catch (const char *msg)
        {
            cerr << endl
                 << msg << endl;
        }
    }
}

/// MAIN
int main()
{
    ofstream operatorsFile("operators.csv", ios::trunc); // Create the files operators.csv, users.csv, routes.csv, and tickets.csv
    if (!operatorsFile.is_open())                        // Add the header to each file
    {
        cerr << "Unable to open operators file!" << endl;
    }
    operatorsFile << "email,password,encryption_key" << endl;
    operatorsFile.close();

    ofstream usersFile("users.csv", ios::trunc);
    if (!usersFile.is_open())
    {
        cerr << "Unable to open users file!" << endl;
    }
    usersFile << "email,password,encryption_key" << endl;
    usersFile.close();

    ofstream routesFile("routes.csv", ios::trunc);
    if (!routesFile.is_open())
    {
        cerr << "Unable to open routes file!" << endl;
    }
    routesFile << "departure,destination,date" << endl;
    routesFile.close();

    ofstream ticketsFile("tickets.csv", ios::trunc);
    if (!ticketsFile.is_open())
    {
        cerr << "Unable to open tickets file!" << endl;
    }
    ticketsFile << "user,departure,destination,date,class,hour" << endl;
    ticketsFile.close();

    Operator tempOperator;
    Operator operator1("operator1@mail.com", "password1"); // Operators are predefined and added to the operators.csv file
    Operator operator2("operator2@mail.com", "password2");

    User tempUser; // Instantiate a User object to be able to call methods from the User class

    while (true)
    {
        int choice = mainMenu();
        switch (choice)
        {
        case 1:
            try
            {
                if (tempOperator.login() == 1)
                {
                    operatorMenu(tempOperator);
                }
            }
            catch (const char *msg)
            {
                cerr << endl
                     << msg << endl;
            }
            break;
        case 2:
            try
            {
                userMenu(tempUser);
            }
            catch (const char *msg)
            {
                cerr << endl
                     << msg << endl;
            }
            break;
        case 3:
            cout << "Exiting program..." << endl;
            return 0;
        default:
            cout << "Invalid option. Please try again." << endl;
            break;
        }
    }
}