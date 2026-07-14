package com.kassiber.app

import android.app.Application
import timber.log.Timber

class KassiberApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) { Timber.plant(Timber.DebugTree()) }
        System.loadLibrary("kassiber_ffi")
        Timber.i("KASSIBER FFI loaded")
    }
}
