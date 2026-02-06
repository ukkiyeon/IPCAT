from case import CaseInfo
from tapo import run_tapo
from smartlife import run_smartlife
from ezviz import run_ezviz
from xiaomi import run_xiaomi

def main():
    case_info = CaseInfo.create_from_input(base_dir="cases")

    while True:
        print("\n=== IP Camera Cloud API Tool ===")
        print(f"Case Folder: {case_info.case_root}")
        print(f"Examiner: {case_info.investigator}")
        print("--------------------------------")
        print("1. EZVIZ")
        print("2. Xiaomi Home")
        print("3. SmartLife(Tuya)")
        print("4. Tapo")
        print("5. Exit")

        choice = input("Select Device No.: ").strip()

        if choice == "1":
            run_ezviz(case_info)

        elif choice == "2":
            run_xiaomi(case_info)

        elif choice == "3":
            run_smartlife(case_info)

        elif choice == "4":
            run_tapo(case_info)

        elif choice == "5":
            print("Exiting.")
            break

        else:
            print("Invalid input. Please try again.")

if __name__ == "__main__":
    main()
