package com.kassiber.app

import android.app.Application
import timber.log.Timber

class KassiberApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) { Timber.plant(Timber.DebugTree()) }
        // The .so only exists after the NDK build (rust_core/build-android.sh)
        // has run on this machine. Until then the app must still start —
        // CryptoBridge degrades to controlled errors instead.
        try {
            System.loadLibrary("kassiber_ffi")
            Timber.i("KASSIBER FFI loaded")
        } catch (e: UnsatisfiedLinkError) {
            Timber.w(e, "libkassiber_ffi.so missing — native crypto unavailable until the NDK build runs")
        }
    }
}
