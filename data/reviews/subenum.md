pip install requests certifi

# بسيط
python subenum.py github.com

# مصدران فقط، بلا كلام
python subenum.py github.com --sources wayback,crt --quiet --pretty

# نص خام للأنابيب
python subenum.py github.com --format text | sort -u | httpx -silent

# عدة نطاقات
echo -e "github.com\ngitlab.com" | python subenum.py --pretty


HackerTarget مجاني لكن بحدود (~50 استعلامًا/يوم)؛ الكود يتعامل مع الحظر برسالة واضحة في errors.

Wayback محدود بطبيعته: limit حتى 10000 يعطي عيّنة لا كل شيء، خصوصًا لنطاقات ضخمة مثل github.com. ارفعه بحذر.

crt.sh كان يعاني انقطاعات في 2024؛ الخيار --sources wayback,crt يستثنيه عند الحاجة.

التحقق من TLS سيستمر في العمل مع web.archive.org وcrt.sh (كلاهما بشهادات صالحة).

verify=False أُزيل نهائيًا — لا مبرر له مع هذه المصادر.

