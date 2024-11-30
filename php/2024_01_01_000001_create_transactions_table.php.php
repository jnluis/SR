<?php

namespace Database\Migrations;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateTransactionsTable extends Migration {
    public function up() {
        Schema::create('transactions', function (Blueprint $table) {
            $table->id();
            $table->string('account_id');
            $table->string('type');
            $table->decimal('amount', 20, 2);
            $table->string('status');
            $table->string('currency', 3);
            $table->text('notes');
            $table->json('metadata');
            $table->timestamps();
            $table->index(['account_id', 'status']);
        });
    }
}