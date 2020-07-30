from django.db import models


# Create your models here.
class ModelWithFileField(models.Model):
    name = models.TextField(max_length=15)
    file_field = models.FileField()
    pub_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name + " от " +str(self.pub_date)

