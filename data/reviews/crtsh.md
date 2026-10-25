pip install requests certifi

# بسيط
python crtsh.py github.com

# JSON منسق مع تضمين النطاق الأساسي وwildcards
python crtsh.py github.com --pretty --include-apex --include-wildcards

# نص خام للأنابيب
python crtsh.py github.com --format text --quiet | sort -u

# عدة نطاقات
python crtsh.py --file domains.txt --quiet --format text

crt.sh ليس API رسميًا — هو واجهة ويب تُستخدم كـ API بشكل غير رسمي. لا ضمانات على الاستقرار. الـ retry والاحتياطي على 503 هما الأساس.

الاستعلام %.{domain} صحيح — يجلب كل الشهادات التي تحتوي النطاق أو أي نطاق فرعي منه، كما يفعل matchType=domain في Wayback.

الفلترة بـ endswith(suffix) مهمة — لأن شهادات SAN قد تحتوي نطاقات غير تابعة (مثل example.org في نفس الشهادة).

إبقاء *. أو حذفها قرار سياقي — في تعداد الأصول، عادةً تُحذف *. لأنها ليست مضيفًا فعليًا؛ في تحليل نطاق الهجوم (attack surface)، تكون *. نفسها معلومة مفيدة.

الاستخدام في أدوات أخرى: ناتج --format text جاهز لـ httpx, dnsx, naabu, أو أي أداة تعداد أخرى.

