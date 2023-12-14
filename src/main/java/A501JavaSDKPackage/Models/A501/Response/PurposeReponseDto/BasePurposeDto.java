package A501JavaSDKPackage.Models.A501.Response.PurposeReponseDto;
import java.util.ArrayList;
import java.util.List;

public class BasePurposeDto {
	public BasePurposeDto() {
		this.HitResponse = new ArrayList<HitDto>();
	}
	public String HitsDetected;
	public Integer HitsCount;
	public String ConfirmedHits;
	public String ReportData;
	public List<HitDto> HitResponse;
	public String CaseId;
	public String CaseUrl;
	public String SuggestedAction;

}
