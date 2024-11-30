<?php

namespace App\Services;

class ValidationService {
    private const ALLOWED_CURRENCIES = ['USD', 'EUR', 'GBP'];

    public function validateTransactionData(array $data): array {
        return [
            'account_id' => $this->sanitizeString($data['account_id']),
            'type' => $this->validateType($data['type']),
            'amount' => $this->validateAmount($data['amount']),
            'currency' => $this->validateCurrency($data['currency']),
            'notes' => $this->sanitizeNotes($data['notes'] ?? ''),
            'metadata' => $this->validateMetadata($data['metadata'] ?? [])
        ];
    }

    private function sanitizeNotes($notes): string {
        if (!is_string($notes)) {
            return '';
        }
        return strip_tags($notes);
    }

    private function validateAmount($amount): float {
        if (!is_numeric($amount) || $amount <= 0) {
            throw new \InvalidArgumentException('Invalid amount');
        }
        return (float) $amount;
    }

    private function validateCurrency($currency): string {
        $currency = strtoupper($currency);
        if (!in_array($currency, self::ALLOWED_CURRENCIES)) {
            throw new \InvalidArgumentException('Invalid currency');
        }
        return $currency;
    }

    private function validateType($type): string {
        if (!TransactionType::tryFrom($type)) {
            throw new \InvalidArgumentException('Invalid transaction type');
        }
        return $type;
    }

    private function sanitizeString($str): string {
        return preg_replace('/[^a-zA-Z0-9_-]/', '', $str);
    }

    private function validateMetadata($metadata): array {
        if (!is_array($metadata)) {
            return [];
        }
        return array_filter($metadata, 'is_scalar');
    }
}