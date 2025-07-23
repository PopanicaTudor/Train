import java.io.File
import kotlin.random.Random

abstract class AccountManager {
    protected fun generateRandomKey(length: Int): String {
        return (1..length)
            .map { Random.nextInt(0, 26) + 'A'.code }
            .map { it.toChar() }
            .joinToString("")
    }

    protected fun vigenereEncrypt(text: String, key: String): String {
        return text.mapIndexed { i, char ->
            val base = if (char.isLowerCase()) 'a' else 'A'
            val shift = key[i % key.length] - 'A'
            ((char - base + shift) % 26 + base.code).toChar()
        }.joinToString("")
    }

    protected fun checkPasswordStrength(password: String): String {
        if (password.length < 8) return "weak"

        val hasLower = password.any { it.isLowerCase() }
        val hasUpper = password.any { it.isUpperCase() }
        val hasDigit = password.any { it.isDigit() }
        val hasSpecial = password.any { it in "!@#$%^&*()-+" }

        return when {
            hasLower && hasUpper && hasDigit && hasSpecial -> "strong"
            (hasLower || hasUpper) && (hasDigit || hasSpecial) -> "ok"
            else -> "weak"
        }
    }

    protected fun login(fileName: String, email: String): Int {
        println("Enter email: ")
        val inputEmail = readLine() ?: throw Exception("Invalid input")
        println("Enter password: ")
        val inputPass = readLine() ?: throw Exception("Invalid input")

        val lines = File(fileName).readLines()
        if (lines.isEmpty()) throw Exception("Empty file")

        val userLine = lines.drop(1).find { it.split(',')[0] == inputEmail }
            ?: throw Exception("Incorrect email!")

        val (_, storedEncryptedPass, storedKey) = userLine.split(',')
        val encryptedInputPass = vigenereEncrypt(inputPass, storedKey)

        return if (encryptedInputPass == storedEncryptedPass) {
            println("\nLogin successful!")
            1
        } else {
            throw Exception("Incorrect password!")
        }
    }

    protected fun registerUser(fileName: String, email: String): Int {
        println("Enter email: ")
        val newEmail = readLine() ?: throw Exception("Invalid input")
        println("Enter password: ")
        val pass = readLine() ?: throw Exception("Invalid input")
        println("Confirm password: ")
        val confirmPass = readLine() ?: throw Exception("Invalid input")

        when {
            newEmail.isEmpty() || pass.isEmpty() || confirmPass.isEmpty() ->
                throw Exception("Please fill in all fields!")
            !newEmail.contains('@') || !newEmail.contains('.') ->
                throw Exception("Invalid email address! Please try again.")
            pass != confirmPass ->
                throw Exception("Passwords do not match! Retry registration.")
            checkPasswordStrength(pass) == "weak" ->
                throw Exception("Password is too weak! Please try again and use a stronger password.")
        }

        val key = generateRandomKey(pass.length)
        val encryptedPass = vigenereEncrypt(pass, key)

        File(fileName).appendText("$newEmail,$encryptedPass,$key\n")
        println("\nUser registered successfully! Password strength: ${checkPasswordStrength(pass)}")
        return 1
    }
}

class TrainRoute(
    private var departure: String = "",
    private var destination: String = "",
    private var date: String = ""
) {
    private fun isValidDate(date: String): Boolean {
        val datePattern = "\\d{2}/\\d{2}/\\d{4}".toRegex()
        if (!date.matches(datePattern)) return false

        val (day, month, year) = date.split("/").map { it.toInt() }
        if (month !in 1..12 || day !in 1..31) return false

        val daysInMonth = intArrayOf(31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
        if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
            daysInMonth[1] = 29
        }

        if (day > daysInMonth[month - 1]) return false

        val current = java.time.LocalDate.now()
        val inputDate = java.time.LocalDate.of(year, month, day)
        return !inputDate.isBefore(current)
    }

    private fun isValidCity(city: String): Boolean {
        return city.matches("^[a-zA-Z]+(?:[\\s-][a-zA-Z]+)*$".toRegex())
    }

    fun addRoute(departure: String, destination: String, date: String) {
        File("routes.csv").appendText("$departure,$destination,$date\n")
    }

    fun deleteRoute(departure: String, destination: String, date: String) {
        val lines = File("routes.csv").readLines()
        if (lines.isEmpty()) throw Exception("Empty file")

        val routeExists = lines.drop(1).any { line ->
            val parts = line.split(",")
            parts[0] == departure && parts[1] == destination && parts[2] == date
        }

        if (!routeExists) throw Exception("Route not found!")

        val updatedLines = lines.filterIndexed { index, line ->
            index == 0 || line != "$departure,$destination,$date"
        }

        File("routes.csv").writeText(updatedLines.joinToString("\n"))
        println("\nRoute deleted successfully: $departure to $destination on $date")
    }
}

interface OperatorOperations {
    fun addRoute()
    fun deleteRoute()
    fun login(): Int
}

class Operator(
    private val email: String = "",
    private val pass: String = ""
) : AccountManager(), OperatorOperations {
    private val trainRoute = TrainRoute()
    private val file = "operators.csv"

    init {
        if (email.isNotEmpty() && pass.isNotEmpty()) {
            File(file).appendText("$email,${vigenereEncrypt(pass, generateRandomKey(pass.length))},${generateRandomKey(pass.length)}\n")
        }
    }

    override fun login(): Int {
        println("\n-----OPERATOR LOGIN-----")
        return super.login(file, email)
    }

    override fun addRoute() {
        println("\n------NEW ROUTE------")
        
        println("Departure: ")
        val departure = readLine() ?: throw Exception("Invalid input")
        
        println("Destination: ")
        val destination = readLine() ?: throw Exception("Invalid input")
        
        println("Date (DD/MM/YYYY): ")
        val date = readLine() ?: throw Exception("Invalid input")

        trainRoute.addRoute(departure, destination, date)
        println("\nRoute added successfully: $departure to $destination on $date")
    }

    override fun deleteRoute() {
        println("\n-----DELETE ROUTE-----")
        
        println("Departure: ")
        val departure = readLine() ?: throw Exception("Invalid input")
        
        println("Destination: ")
        val destination = readLine() ?: throw Exception("Invalid input")
        
        println("Date (DD/MM/YYYY): ")
        val date = readLine() ?: throw Exception("Invalid input")

        trainRoute.deleteRoute(departure, destination, date)
    }
}

class User(
    private var email: String = "",
    private var pass: String = ""
) : AccountManager() {
    private val file = "users.csv"
    private val trainRoute = TrainRoute()

    init {
        if (email.isNotEmpty() && pass.isNotEmpty()) {
            File(file).appendText("$email,${vigenereEncrypt(pass, generateRandomKey(pass.length))},${generateRandomKey(pass.length)}\n")
        }
    }

    fun registerUser(): Int {
        println("\n-----USER REGISTRATION-----")
        return super.registerUser(file, email)
    }

    fun login(): Int {
        println("\n------USER LOGIN------")
        return super.login(file, email)
    }

    public fun findRoute(departure: String, destination: String, date: String): Int {
        val lines = File("routes.csv").readLines()
        if (lines.isEmpty()) throw Exception("Empty file")

        val routeExists = lines.drop(1).any { line ->
            val parts = line.split(',')
            parts[0] == departure && parts[1] == destination && parts[2] == date
        }

        return if (routeExists) {
            println("\nRoute found: $departure to $destination on $date")
            1
        } else {
            throw Exception("Route not found!")
        }
    }

    fun bookTicket() {
        println("\n-----BOOK TICKET-----")
        
        println("Departure: ")
        val departure = readLine() ?: throw Exception("Invalid input")
        
        println("Destination: ")
        val destination = readLine() ?: throw Exception("Invalid input")
        
        println("Date (DD/MM/YYYY): ")
        val date = readLine() ?: throw Exception("Invalid input")

        if (findRoute(departure, destination, date) == 1) {
            println("Route is available!\n\nWhat class do you want?\n1. First Class\n2. Second Class\n3. Business Class\n4. Economy Class\n\nChoose an option: ")
            val choice = readLine()?.toIntOrNull() ?: throw Exception("Invalid input")

            if (choice !in 1..4) throw Exception("Invalid option")

            val classOption = when (choice) {
                1 -> "First Class"
                2 -> "Second Class"
                3 -> "Business Class"
                4 -> "Economy Class"
                else -> throw Exception("Invalid option")
            }

            println("Choose an hour (0-23): ")
            val hour = readLine()?.toIntOrNull() ?: throw Exception("Invalid input")
            if (hour !in 0..23) throw Exception("Invalid hour")

            File("tickets.csv").appendText("$email,$departure,$destination,$date,$classOption,$hour\n")
            println("\nTicket booked successfully!\nDeparture: $departure\nDestination: $destination\nDate: $date\nClass: $classOption\nHour: $hour")
        }
    }
}

fun operatorMenu(operator: Operator) {
    while (true) {
        println("\n-----OPERATOR MENU-----")
        println("1. Add Route")
        println("2. Delete Route") 
        println("3. Logout")
        println("\nChoose an option: ")

        try {
            when (readLine()?.toIntOrNull() ?: throw Exception("Invalid input")) {
                1 -> operator.addRoute()
                2 -> operator.deleteRoute()
                3 -> return
                else -> throw Exception("Invalid option. Please try again.")
            }
        } catch (e: Exception) {
            println("\n${e.message}")
        }
    }
}

fun userMenu(user: User) {
    var loggedIn = false
    
    while (true) {
        println("\n-----USER MENU-----")
        println("1. Register")
        println("2. Login")
        println("3. Search Route")
        println("4. Book Ticket")
        println("5. Logout")
        println("\nChoose an option: ")

        try {
            when (readLine()?.toIntOrNull() ?: throw Exception("Invalid input")) {
                1 -> if (user.registerUser() == 1) loggedIn = true
                2 -> if (user.login() == 1) loggedIn = true
                3 -> {
                    if (!loggedIn) throw Exception("Please login first!")
                    println("\n-----SEARCH ROUTE-----")
                    println("Departure: ")
                    val departure = readLine() ?: throw Exception("Invalid input")
                    println("Destination: ")
                    val destination = readLine() ?: throw Exception("Invalid input") 
                    println("Date (DD/MM/YYYY): ")
                    val date = readLine() ?: throw Exception("Invalid input")
                    if (isValidDate(date) && isValidCity(departure) && isValidCity(destination))
                        user.findRoute(departure, destination, date)
                }
                4 -> {
                    if (!loggedIn) throw Exception("Please login first!")
                    user.bookTicket()
                }
                5 -> return
                else -> throw Exception("Invalid option. Please try again.")
            }
        } catch (e: Exception) {
            println("\n${e.message}")
        }
    }
}

fun mainMenu(): Int {
    println("\n------MAIN MENU------")
    println("1. Operator")
    println("2. User")
    println("3. Exit")
    println("\nChoose an option: ")
    return readLine()?.toIntOrNull() ?: throw Exception("Invalid input")
}

fun main() {
    File("operators.csv").writeText("email,password,encryption_key\n")
    File("users.csv").writeText("email,password,encryption_key\n")
    File("routes.csv").writeText("departure,destination,date\n")
    File("tickets.csv").writeText("user,departure,destination,date,class,hour\n")

    val tempOperator = Operator()
    Operator("operator1@mail.com", "password1")
    Operator("operator2@mail.com", "password2")

    val tempUser = User()

    while (true) {
        try {
            when (mainMenu()) {
                1 -> if (tempOperator.login() == 1) {
                    operatorMenu(tempOperator)
                }
                2 -> userMenu(tempUser)
                3 -> {
                    println("Exiting program...")
                    return
                }
                else -> println("Invalid option. Please try again.")
            }
        } catch (e: Exception) {
            println("\n${e.message}")
        }
    }
}