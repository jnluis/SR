<?php

use Illuminate\Database\Eloquent\Model;

class Transaction extends Model {
    protected $fillable = [
        'account_id',
        'type',
        'amount',
        'status',
        'currency',
        'notes',
        'metadata'
    ];

    protected $casts = [
        'amount' => 'decimal:2',
        'metadata' => 'array'
    ];
}