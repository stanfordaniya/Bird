import hashlib
import threading

stop_cracker = threading.Event()

def crack_password(hash_to_crack, dictionary_file, update_function):
    def worker():
        with open(dictionary_file, 'r') as file:
            for line in file:
                if stop_cracker.is_set():
                    update_function("Password cracking stopped by user")
                    return
                word = line.strip()
                if hashlib.md5(word.encode()).hexdigest() == hash_to_crack:
                    update_function(f"Password found: {word}")
                    return
        update_function("Password not found")

    thread = threading.Thread(target=worker)
    thread.start()

def stop_cracking():
    stop_cracker.set()
