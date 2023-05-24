from django.shortcuts import render

# Create your views here.
def review(request):
    if request.method == "POST":
        userName = request.POST['username']
    return render(request, "/Users/maxwardle/Desktop/Django/Projects/Forms/Feedback/reviews/templates/review.html")

