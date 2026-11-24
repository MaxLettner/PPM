package dev.peerpass

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Background sync while the app is closed: ~30 s of discover → sync → stop. Works locked. */
class SyncWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val app = applicationContext as PeerPassApp
        Net.acquire(app)
        try {
            app.core.backgroundSync(30u)
        } finally {
            if (!MainActivity.visible) Net.release()
        }
        Vault.bump()
        Result.success()
    }

    companion object {
        // Unmetered ≈ connected Wi-Fi (the only network where peers can be).
        private val wifi = Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).build()

        fun schedulePeriodic(c: Context) {
            val req = PeriodicWorkRequestBuilder<SyncWorker>(15, TimeUnit.MINUTES).setConstraints(wifi).build()
            WorkManager.getInstance(c).enqueueUniquePeriodicWork("sync", ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun syncSoon(c: Context) {
            val req = OneTimeWorkRequestBuilder<SyncWorker>()
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .setConstraints(wifi)
                .build()
            WorkManager.getInstance(c).enqueueUniqueWork("sync-now", ExistingWorkPolicy.REPLACE, req)
        }
    }
}
