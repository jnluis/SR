# PHP Assessment

## Vulnerability 1 - SQL Injection 
The $schema below uses invalidated data from $data and allows dangerous user input to be passed on as a table name.

```php
$accountTable = sprintf('%s.accounts', $schema);
$account = DB::table($accountTable)
            ->where('id', $validated['account_id'])
            ->first();
```
in processTransaction function, in TransactionProcessor.php.

### Solution 1:

Don't use dynamic table names, with improper validation.

## Vulnerability 2 - XSS attack

The code below uses a function that while removing HTML tags, it still does not address encoding or contextual output issues, which are crucial to preventing XSS.

```PHP
private function sanitizeNotes($notes): string {
    if (!is_string($notes)) {
        return '';
    }
    return strip_tags($notes);
}
```
in sanitizeNotes() function, in ValidationService.php.

### Solution 2:

Instead of using strip_tags() function, use a function that escapes the input such as the function on the right. 

Code:
```php
private function sanitizeNotes ($notes): string {
    return htmlspecialchars($notes, ENT_QUOTES, 'UTF-8');
}
 ```

## Vulnerability 3 - Resource Leak

Database Transactions are not being closed Properly, leading to potential deadlock behavior, memory exhaustion, etc...

```php
if ($complianceResult->status === 'compliance_review') {
  return ['status' => 'compliance_review'];
} 
```
in processTransaction() function, line 49, in TransactionProcessor.php.

### Solution 3:

```php
if ($complianceResult->status === 'compliance_review') {
  DB::rollBack();
  return ['status' => 'compliance_review'];
}
```

Ensure transactions are always rolled back or committed. We can also use DB::transaction() method, instead of beginTransaction(), commit() and rollBack().
