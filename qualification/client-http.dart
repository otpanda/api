import 'dart:convert';
import 'dart:io';
import '../client-app/lib/totp_batch_contract.dart';
Future<void> main(List<String> args) async {
 final fixture=jsonDecode(File('qualification/fixture.json').readAsStringSync()) as Map;
 final ids=(fixture['ids'] as List).cast<String>().take(3).toSet();
 final uri=Uri.parse('${args.single}/v1/manage/totp-codes').replace(queryParameters:{'entry':ids.toList(),'window':'600'});
 final client=HttpClient(), watch=Stopwatch()..start();
 final store=BatchCodeStore(monotonicMilliseconds:()=>watch.elapsedMilliseconds);
 const policy=BatchPolicy(maxEntries:3,maxTotalCodes:100,minPeriodSeconds:20,maxPeriodSeconds:86400,maxWindowSeconds:600,minRemainingMs:1);
 try {for(var i=0;i<2;i++) {
  final ticket=store.begin(ids);final req=await client.getUrl(uri);req.headers.set('Authorization','Bearer ${fixture['access']}');
  final response=await req.close();if(response.statusCode!=200)throw StateError('HTTP ${response.statusCode}');
  final envelope=jsonDecode(await utf8.decoder.bind(response).join()) as Map;
  if(!store.accept(ticket,envelope['body'],policy:policy))throw StateError('Rejected response');
  if(!ids.every((id)=>store.current(id)!=null))throw StateError('Missing current code');
  stdout.writeln(jsonEncode({'client':'exact Dart BatchCodeStore','status':response.statusCode,'accounts':ids.length,'copyableCurrentCodes':store.available().length,'totalCodes':envelope['body']['totalCodes']}));
 }}finally {client.close(force:true);store.clear();}
}
