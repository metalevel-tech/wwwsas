### Use the following command to replace 'example.com' with 'your.doman' before the file population:

    find . -type f -exec sed -i 's/example\.com/your\.domain/g' {} \;

#### Check the changes:

    grep -rni 'your.domain' .
