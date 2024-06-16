class Samsung:
    def company_details():
        print("Website = www.samsung.com /n Address = 250A cherry road Madurai")
class Samsung_Model_J7Max(Samsung):
    def model_details():
        print("RAM = 16 GB /n Rom = 512GB")
Obj=Samsung_Model_J7Max()
res=Obj.company_details()
print(res)