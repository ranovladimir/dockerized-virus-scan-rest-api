using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using nClam;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace scan.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AntivirusScanController : ControllerBase
    {
        private readonly ILogger<AntivirusScanController> _logger;
        private readonly IConfiguration _configuration;

        public AntivirusScanController(ILogger<AntivirusScanController> logger
            , IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("Scan")]
        public async Task<IActionResult> Scan([FromForm] FileUpload fileUpload)
        {
            var ms = new MemoryStream();
            fileUpload.file.OpenReadStream().CopyTo(ms);
            byte[] fileBytes = ms.ToArray();
            bool isFileClean = false;
            try
            {
                this._logger.LogInformation("ClamAV scan begin for file {0}", fileUpload.file.FileName);
                // var clam = new ClamClient(this._configuration["ClamAVServer:URL"],
                //   Convert.ToInt32(this._configuration["ClamAVServer:Port"]));

                //var clam = new ClamClient("localhost", 3310);

                // First parameter could be the container ip (if link via network) or container name.
                var clam = new ClamClient("172.18.0.3", 3310);


                var scanResult = await clam.SendAndScanFileAsync(fileBytes);
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        this._logger.LogInformation("The file is clean! ScanResult:{1}", scanResult.RawResult);
                        break;
                    case ClamScanResults.VirusDetected:
                        this._logger.LogError("Virus Found! Virus name: {1}", scanResult.InfectedFiles.FirstOrDefault().VirusName);
                        break;
                    case ClamScanResults.Error:
                        this._logger.LogError("An error occured while scaning the file! ScanResult: {1}", scanResult.RawResult);
                        break;
                    case ClamScanResults.Unknown:
                        this._logger.LogError("Unknown scan result while scaning the file! ScanResult: {0}", scanResult.RawResult);
                        break;
                }

                if (scanResult.Result == ClamScanResults.Clean)
                {
                    isFileClean = true;
                }

            }
            catch (Exception ex)
            {

                this._logger.LogError("ClamAV Scan Exception: {0}", ex.ToString());
            }
            this._logger.LogInformation("ClamAV scan completed for file {0}", fileUpload.file.FileName);

            return Ok(isFileClean);
        }
    }

    public class FileUpload
    {
        public IFormFile file { get; set; }
    }
}
